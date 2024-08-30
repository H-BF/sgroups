package main

import (
	"context"
	"flag"
	"os"
	"sync"
	"time"

	"github.com/H-BF/sgroups/internal/app"
	. "github.com/H-BF/sgroups/internal/app/agent" //nolint:revive
	"github.com/H-BF/sgroups/internal/app/agent/jobs"
	"github.com/H-BF/sgroups/internal/app/agent/nft"

	"github.com/H-BF/corlib/logger"
	pkgNet "github.com/H-BF/corlib/pkg/net"
	"github.com/H-BF/corlib/pkg/nl"
	"github.com/H-BF/corlib/pkg/parallel"
	gs "github.com/H-BF/corlib/pkg/patterns/graceful-shutdown"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	config "github.com/H-BF/corlib/pkg/plain-config"
	"github.com/H-BF/corlib/server"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

func init() {
	if false {
		//TODO: REMOVE THIS
		os.Setenv("NFT_NETNS", "ns1")
		//os.Setenv("NFT_FQDN-RULES_STRATEGY", "ndpi")
	}
	if false {
		os.Setenv("NFT_EXTAPI_SVC_SGROUPS_AUTHN_TYPE", "tls")
		os.Setenv("NFT_EXTAPI_SVC_SGROUPS_AUTHN_TLS_SERVER_VERIFY", "true")
		os.Setenv("NFT_EXTAPI_SVC_SGROUPS_AUTHN_TLS_SERVER_CA-FILES", `["./tls/ca-cert.pem"]`)
		os.Setenv("NFT_EXTAPI_SVC_SGROUPS_AUTHN_TLS_SERVER_NAME", "serv0")

		os.Setenv("NFT_EXTAPI_SVC_SGROUPS_SYNC-STATUS_PUSH", "true")
	}
}

func main() { //nolint:gocyclo
	flag.Parse()
	SetupContext()
	SetupAgentSubject()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= HELLO =-")
	err := config.InitGlobalConfig(
		config.WithAcceptEnvironment{EnvPrefix: "NFT"},
		config.WithSourceFile{FileName: ConfigFile},
		config.WithDefValue(ExitOnSuccess, false),
		config.WithDefValue(ContinueOnFailure, true),
		config.WithDefValue(ContinueAfterTimeout, "10s"),
		//config.WithDefValue(BaseRulesOutNets,   `["192.168.1.0/24","192.168.2.0/24"]`),
		config.WithDefValue(FqdnStrategy, FqdnRulesStartegyDNS),
		config.WithDefValue(AppLoggerLevel, "DEBUG"),
		config.WithDefValue(AppGracefulShutdown, 10*time.Second), //nolint:mnd
		config.WithDefValue(NetNS, ""),
		config.WithDefValue(NetlinkWatcherLinger, "10s"),
		config.WithDefValue(ServicesDefDialDuration, 10*time.Second), //nolint:mnd
		config.WithDefValue(SGroupsAddress, "tcp://127.0.0.1:9000"),
		config.WithDefValue(SGroupsSyncStatusInterval, "10s"),
		config.WithDefValue(SGroupsSyncStatusPush, false),
		config.WithDefValue(SGroupsUseJsonCodec, false),
		//DNS group
		config.WithDefValue(DnsNameservers, `["8.8.8.8"]`),
		config.WithDefValue(DnsProto, "udp"),
		config.WithDefValue(DnsPort, 53),   //nolint:mnd
		config.WithDefValue(DnsRetries, 3), //nolint:mnd
		config.WithDefValue(DnsRetriesTmo, "1s"),
		config.WithDefValue(DnsDialDuration, "3s"),
		config.WithDefValue(DnsWriteDuration, "5s"),
		config.WithDefValue(DnsReadDuration, "5s"),
		//telemetry group
		config.WithDefValue(TelemetryEndpoint, "127.0.0.1:5000"),
		config.WithDefValue(MetricsEnable, true),
		config.WithDefValue(HealthcheckEnable, true),
		config.WithDefValue(UserAgent, ""),
		config.WithDefValue(ProfileEnable, true),
		config.WithDefValue(NftablesCollectorMinFrequency, "10s"),
		//authn group
		config.WithDefValue(SGroupsAuthnType, config.AuthnTypeNONE),
	)
	if err != nil {
		logger.Fatal(ctx, err)
	}

	if err = SetupLogger(); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup logger"))
	}
	if err = SetupMetrics(ctx); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup metrics"))
	}

	err = WhenSetupTelemtryServer(ctx, func(srv *server.APIServer) error {
		addr := TelemetryEndpoint.MustValue(ctx)
		ep, e := pkgNet.ParseEndpoint(addr)
		if e != nil {
			return errors.WithMessagef(e, "parse telemetry endpoint (%s): %v", addr, e)
		}
		go func() { //start telemetry endpoint
			if e1 := srv.Run(ctx, ep); e1 != nil {
				logger.Fatalf(ctx, "telemetry server is failed: %v", e1)
			}
		}()
		return nil
	})
	if err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup telemetry server"))
	}

	if err = SetupDnsResolver(ctx); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup DNS resolver"))
	}

	if exitOnSuccess := ExitOnSuccess.MustValue(ctx); exitOnSuccess {
		o := observer.NewObserver(exitOnSuccessHanler,
			true,
			jobs.AppliedConfEvent{},
		)
		AgentSubject().ObserversAttach(o)
	}

	AgentSubject().ObserversAttach(
		observer.NewObserver(agentMetricsObserver,
			false,
			jobs.AppliedConfEvent{},
			SyncStatusError{},
			NetlinkError{},
			jobs.DomainAddresses{}),
	)

	gracefulDuration := AppGracefulShutdown.MustValue(ctx)
	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		errc <- runNftJob(ctx)
	}()
	var jobErr error
	select {
	case <-ctx.Done():
		if gracefulDuration >= time.Second {
			logger.Infof(ctx, "%s in shutdowning...", gracefulDuration)
			_ = gs.ForDuration(gracefulDuration).Run(
				gs.Chan(errc).Consume(
					func(_ context.Context, err error) {
						jobErr = err
					},
				),
			)
		}
	case jobErr = <-errc:
	}
	if jobErr != nil {
		logger.Fatal(ctx, jobErr)
	}
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}

func exitOnSuccessHanler(ev observer.EventType) {
	switch ev.(type) {
	case jobs.AppliedConfEvent:
		os.Exit(0)
	}
	os.Exit(1)
}

func agentMetricsObserver(ev observer.EventType) {
	if metrics := GetAgentMetrics(); metrics != nil {
		switch o := ev.(type) {
		case jobs.AppliedConfEvent:
			metrics.ObserveApplyConfig()
		case SyncStatusError:
			metrics.ObserveError(ESrcSgBakend)
		case NetlinkError:
			metrics.ObserveError(ESrcNetWatcher)
		case jobs.DomainAddresses:
			if o.DnsAnswer.Err != nil {
				metrics.ObserveError(ESrcDNS)
			}
		}
	}
}

func runNftJob(ctx context.Context) (err error) {
	var waitBeforeRestart time.Duration
	if waitBeforeRestart, err = ContinueAfterTimeout.Value(ctx); err != nil {
		return err
	}

	ctx1 := logger.ToContext(ctx,
		logger.FromContext(ctx).Named("main"),
	)

	logger.Infof(ctx1, "start")
	defer logger.Infof(ctx1, "exit")
	for {
		var jb mainJob
		if err = jb.init(ctx1); err != nil {
			break
		}
		if err = jb.run(ctx1); err == nil {
			break
		}
		if !jb.continueOnFailure {
			logger.Info(ctx1, "will exit cause 'ContinueOnFailure' policy is off")
			break
		}
		logger.Infof(ctx1, "will retry after %s", waitBeforeRestart)
		if waitBeforeRestart >= time.Second {
			select {
			case <-time.After(waitBeforeRestart):
			case <-ctx.Done():
				return nil
			}
		}
	}
	return err
}

func makeNetlinkWatcher(ctx context.Context, netNs string) (nl.NetlinkWatcher, error) {
	opts := []nl.WatcherOption{
		nl.IgnoreLinks,
		nl.WithLinger{
			Linger: NetlinkWatcherLinger.MustValue(ctx),
		},
	}
	if len(netNs) > 0 {
		opts = append(opts, nl.WithNetnsName(netNs))
	}
	nlWatcher, err := nl.NewNetlinkWatcher(opts...)
	return nlWatcher, errors.WithMessage(err, "create net-watcher")
}

func makeNftprocessor(ctx context.Context, sgClient SGClient, netNs string) (nft.NfTablesProcessor, error) {
	var opts []nft.NfTablesProcessorOpt
	if len(netNs) > 0 {
		opts = append(opts, nft.WithNetNS{NetNS: netNs})
	}
	err := nft.IfBaseRulesFromConfig(ctx, func(br nft.BaseRules) error {
		opts = append(opts, br)
		return nil
	})
	if err != nil {
		return nil, errors.WithMessage(err, "load base rules")
	}
	return nft.NewNfTablesProcessor(sgClient, opts...), nil
}

type mainJob struct {
	netNs                   string
	SyncStatusCheckInterval time.Duration
	SyncStatusUsePush       bool
	nftProcessor            nft.NfTablesProcessor
	sgClient                *SGClient
	nlWatcher               nl.NetlinkWatcher
	continueOnFailure       bool
}

func (m *mainJob) cleanup() {
	if m.nlWatcher != nil {
		_ = m.nlWatcher.Close()
	}
	if m.nftProcessor != nil {
		_ = m.nftProcessor.Close()
	}
	if m.sgClient != nil {
		m.sgClient.CloseConn() //nolint:errcheck
	}
}

func (m *mainJob) init(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			m.cleanup()
		}
	}()
	m.netNs, err = NetNS.Value(ctx)
	if err != nil && !errors.Is(err, config.ErrNotFound) {
		return err
	}
	m.continueOnFailure = ContinueOnFailure.MustValue(ctx)
	m.SyncStatusCheckInterval = SGroupsSyncStatusInterval.MustValue(ctx)
	m.SyncStatusUsePush = SGroupsSyncStatusPush.MustValue(ctx)
	if m.sgClient, err = NewSGClient(ctx); err != nil {
		return err
	}
	if m.nlWatcher, err = makeNetlinkWatcher(ctx, m.netNs); err != nil {
		return err
	}
	if m.nftProcessor, err = makeNftprocessor(ctx, *m.sgClient, m.netNs); err != nil {
		return err
	}
	return nil
}

func (m *mainJob) run(ctx context.Context) error {
	defer m.cleanup()
	subject := NewTiedSubj(AgentSubject())
	nftApplier := jobs.NewNftApplierJob(m.nftProcessor, *m.sgClient,
		jobs.WithSubject{Subject: subject},
		jobs.WithNetNS(m.netNs),
	)
	nle := NetlinkEventSource{
		Subject:        subject,
		NetlinkWatcher: m.nlWatcher,
		NetNS:          m.netNs,
	}
	ste := SyncStatusEventSource{
		Subject:       subject,
		SGClient:      *m.sgClient,
		CheckInterval: m.SyncStatusCheckInterval,
		UsePushModel:  m.SyncStatusUsePush,
	}
	dnsRf := jobs.NewDnsRefresher(subject)

	ctx1, cancel := context.WithCancel(ctx)
	observers := [...]observer.Observer{
		nftApplier.MakeObserver(), dnsRf.MakeObserver(ctx1),
	}
	subject.ObserversAttach(observers[:]...)

	ff := [...]func() error{
		func() error {
			HcNftApplier.Set(true)
			defer HcNftApplier.Set(false)
			return nftApplier.Run(ctx1)
		},
		func() error {
			HcNetConfWatcher.Set(true)
			defer HcNetConfWatcher.Set(false)
			return nle.Run(ctx1)
		},
		func() error {
			HcSyncStatus.Set(true)
			defer HcSyncStatus.Set(false)
			return ste.Run(ctx1)
		},
		func() error {
			HcDnsRefresher.Set(true)
			defer HcDnsRefresher.Set(false)
			return dnsRf.Run(ctx1)
		},
	}
	fnClose := func() {
		subject.DetachAllObservers()
		for _, o := range observers {
			_ = o.Close()
		}
		_ = dnsRf.Close()
		_ = nle.Close()
		_ = nftApplier.Close()
		cancel()
	}
	var closeOnce sync.Once
	n := len(ff)
	errs := make([]error, n)
	_ = parallel.ExecAbstract(n, int32(n-1), func(i int) error {
		errs[i] = ff[i]()
		closeOnce.Do(fnClose)
		return nil
	})
	select {
	case <-ctx.Done():
		return nil
	default:
	}
	return multierr.Combine(errs...)
}
