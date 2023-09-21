package main

import (
	"context"
	"flag"
	"os"
	"time"

	. "github.com/H-BF/sgroups/cmd/to-nft/internal" //nolint:revive
	"github.com/H-BF/sgroups/cmd/to-nft/internal/dns"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/jobs"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft"
	"github.com/H-BF/sgroups/internal/app"
	"github.com/H-BF/sgroups/internal/config"
	"github.com/H-BF/sgroups/pkg/nl"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/parallel"
	gs "github.com/H-BF/corlib/pkg/patterns/graceful-shutdown"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

func main() {
	flag.Parse()
	SetupContext()
	SetupAgentSubject()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= HELLO =-")

	if false {
		//TODO: REMOVE THIS
		os.Setenv("NFT_NETNS", "ns1")
	}

	err := config.InitGlobalConfig(
		config.WithAcceptEnvironment{EnvPrefix: "NFT"},
		config.WithSourceFile{FileName: ConfigFile},
		config.WithDefValue{Key: ExitOnSuccess, Val: false},
		config.WithDefValue{Key: ContinueOnFailure, Val: false},
		//config.WithDefValue{Key: BaseRulesOutNets, Val: `["192.168.1.0/24","192.168.2.0/24"]`},
		config.WithDefValue{Key: AppLoggerLevel, Val: "DEBUG"},
		config.WithDefValue{Key: AppGracefulShutdown, Val: 10 * time.Second},
		config.WithDefValue{Key: NetNS, Val: ""},
		config.WithDefValue{Key: ServicesDefDialDuration, Val: 10 * time.Second},
		config.WithDefValue{Key: SGroupsAddress, Val: "tcp://127.0.0.1:9000"},
		config.WithDefValue{Key: SGroupsSyncStatusInterval, Val: "30s"},
		//DNS group
		config.WithDefValue{Key: DnsNameservers, Val: `["8.8.8.8"]`},
		config.WithDefValue{Key: DnsProto, Val: "udp"},
		config.WithDefValue{Key: DnsPort, Val: 53},
		config.WithDefValue{Key: DnsRetries, Val: 3},
		config.WithDefValue{Key: DnsRetriesTmo, Val: "1s"},
		config.WithDefValue{Key: DnsDialDuration, Val: "3s"},
		config.WithDefValue{Key: DnsWriteDuration, Val: "5s"},
		config.WithDefValue{Key: DnsReadDuration, Val: "5s"},
	)
	if err != nil {
		logger.Fatal(ctx, err)
	}
	if err = SetupLogger(); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup logger"))
	}

	if exitOnSuccess := ExitOnSuccess.MustValue(ctx); exitOnSuccess {
		o := observer.NewObserver(exitOnSuccessHanler,
			true,
			jobs.AppliedConfEvent{},
		)
		AgentSubject().ObserversAttach(o)
	}

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

func exitOnSuccessHanler(_ observer.EventType) {
	os.Exit(0)
}

func runNftJob(ctx context.Context) (err error) {
	const waitBeforeRestart = 10 * time.Second

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
			break
		}
		logger.Errorf(ctx1, "%v", err)
		logger.Infof(ctx1, "will retry after '%s'", waitBeforeRestart)
		select {
		case <-time.After(waitBeforeRestart):
		case <-ctx.Done():
			return nil
		}
	}
	return err
}

func makeNetlinkWatcher(netNs string) (nl.NetlinkWatcher, error) {
	opts := []nl.WatcherOption{
		nl.WithLinger{Linger: 10 * time.Second},
	}
	if len(netNs) > 0 {
		opts = append(opts, nl.WithNetns{Netns: netNs})
	}
	nlWatcher, err := nl.NewNetlinkWatcher(opts...)
	return nlWatcher, errors.WithMessage(err, "create net-watcher")
}

func makeNftprocessor(ctx context.Context, sgClient SGClient, netNs string) (nft.NfTablesProcessor, error) {
	dns.NewDomainAddressQuerier(ctx)
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
	var dnsQuerier dns.DomainAddressQuerier
	if dnsQuerier, err = dns.NewDomainAddressQuerier(ctx); err != nil {
		return nil, err
	}
	opts = append(opts, nft.DnsResolver{DomainAddressQuerier: dnsQuerier})
	return nft.NewNfTablesProcessor(sgClient, opts...), nil
}

type mainJob struct {
	appSubject              observer.Subject
	netNs                   string
	SyncStatusCheckInterval time.Duration
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
		m.sgClient.CloseConn()
	}
}

func (m *mainJob) init(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			m.cleanup()
		}
	}()
	m.appSubject = AgentSubject()
	m.netNs, err = NetNS.Value(ctx)
	if err != nil && !errors.Is(err, config.ErrNotFound) {
		return err
	}
	m.continueOnFailure = ContinueOnFailure.MustValue(ctx)
	m.SyncStatusCheckInterval = SGroupsSyncStatusInterval.MustValue(ctx)
	if m.sgClient, err = NewSGClient(ctx); err != nil {
		return err
	}
	if m.nlWatcher, err = makeNetlinkWatcher(m.netNs); err != nil {
		return err
	}
	if m.nftProcessor, err = makeNftprocessor(ctx, *m.sgClient, m.netNs); err != nil {
		return err
	}
	return nil
}

func (m *mainJob) run(ctx context.Context) error {
	defer m.cleanup()
	jb := jobs.NewNftApplierJob(m.nftProcessor,
		jobs.WithAgentSubject{Subject: m.appSubject})
	defer jb.Close()
	nle := NetlinkEventSource{
		AgentSubj:      m.appSubject,
		NetlinkWatcher: m.nlWatcher,
	}
	ste := SyncStatusEventSource{
		AgentSubj:     m.appSubject,
		SGClient:      *m.sgClient,
		CheckInterval: m.SyncStatusCheckInterval,
	}
	ctx1, cancel := context.WithCancel(ctx)
	defer cancel()
	ff := []func() error{
		func() error {
			return jb.Run(ctx1)
		},
		func() error {
			return nle.Run(ctx1)
		},
		func() error {
			return ste.Run(ctx1)
		},
	}
	errs := make([]error, len(ff))
	_ = parallel.ExecAbstract(len(ff), 2, func(i int) error {
		if e := ff[i](); e != nil {
			cancel()
			if !errors.Is(e, context.Canceled) {
				errs[i] = e
			}
		}
		return nil
	})
	return multierr.Combine(errs...)
}
