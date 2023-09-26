package main

import (
	"context"
	"flag"
	"os"
	"time"

	. "github.com/H-BF/sgroups/cmd/to-nft/internal" //nolint:revive
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft"
	"github.com/H-BF/sgroups/internal/app"
	"github.com/H-BF/sgroups/internal/config"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/pkg/nl"

	"github.com/H-BF/corlib/logger"
	gs "github.com/H-BF/corlib/pkg/patterns/graceful-shutdown"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
)

func main() {
	flag.Parse()
	SetupContext()
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
		//config.WithDefValue{Key: BaseRulesOutNets, Val: `["192.168.1.0/24","192.168.2.0/24"]`},
		config.WithDefValue{Key: AppLoggerLevel, Val: "DEBUG"},
		config.WithDefValue{Key: AppGracefulShutdown, Val: 10 * time.Second},
		config.WithDefValue{Key: NetNS, Val: ""},
		config.WithDefValue{Key: ServicesDefDialDuration, Val: 10 * time.Second},
		config.WithDefValue{Key: SGroupsAddress, Val: "tcp://127.0.0.1:9000"},
		config.WithDefValue{Key: SGroupsSyncStatusInterval, Val: "30s"},
	)
	if err != nil {
		logger.Fatal(ctx, err)
	}
	if err = SetupLogger(); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup logger"))
	}

	gracefulDuration, _ := AppGracefulShutdown.Value(ctx)
	errc := make(chan error, 1)

	go func() {
		logger.Infof(ctx, "nft-processor start")
		errc <- runNftJob(ctx)
		close(errc)
		logger.Infof(ctx, "nft-processor stop")
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

func runNftJob(ctx context.Context) error { //nolint:gocyclo
	var (
		err           error
		exitOnSuccess bool
		sgClient      SGClient
		nlWatcher     nl.NetlinkWatcher
		nftProc       nft.NfTablesProcessor
	)
	if exitOnSuccess, err = ExitOnSuccess.Value(ctx); err != nil {
		return err
	}

	if sgClient, err = NewSGClient(ctx); err != nil {
		return err
	}
	defer sgClient.CloseConn() //nolint:errcheck

	netNs, _ := NetNS.Value(ctx)
	netWathOpts := []nl.WatcherOption{
		nl.WithAgeOfMaturity{Age: 10 * time.Second},
		nl.WithNetns{Netns: netNs},
	}
	if nlWatcher, err = nl.NewNetlinkWatcher(netWathOpts...); err != nil {
		return errors.WithMessage(err, "create net-watcher")
	}
	defer nlWatcher.Close()

	var opts []nft.NfTablesProcessorOpt
	if len(netNs) > 0 {
		opts = append(opts, nft.WithNetNS{NetNS: netNs})
	}
	err = nft.IfBaseRulesFromConfig(ctx, func(br nft.BaseRules) error {
		opts = append(opts, br)
		return nil
	})
	if err != nil {
		return errors.WithMessage(err, "load base rules")
	}
	nftProc = nft.NewNfTablesProcessor(sgClient, opts...)
	defer nftProc.Close()

	var conf nft.NetConf
	conf.Init()
	stm := nlWatcher.Stream()

	syncStatusCh := getSyncStatuses(ctx, sgClient)
	prevStatus := <-syncStatusCh

	var appliedCount int
loop0:
	for needApply := false; ; needApply = false {
		select {
		case <-ctx.Done():
			break loop0
		case msgs := <-stm:
			for _, m := range msgs {
				if e, ok := m.(nl.ErrMsg); ok {
					if errors.Is(e.Err, nl.ErrUnexpectedlyStopped) {
						err = e
						break loop0
					}
					logger.ErrorKV(ctx, "net-watcher", "error", e)
				}
			}
			needApply = conf.UpdFromWatcher(msgs...) != 0
		case st := <-syncStatusCh:
			if appliedCount != 0 {
				needApply = !prevStatus.UpdatedAt.Equal(st.UpdatedAt)
				prevStatus = st
			}
		}
		if needApply || appliedCount == 0 {
			appliedCount++
			logger.Infof(ctx, "net-conf will apply now")
			if err = nftProc.ApplyConf(ctx, conf); err != nil {
				logger.Errorf(ctx, "net-conf din`t apply")
				break
			}
			logger.Infof(ctx, "net-conf applied")
			if exitOnSuccess {
				break loop0
			}
		}
	}
	return err
}

func getSyncStatuses(ctx context.Context, c SGClient) <-chan model.SyncStatus {
	const timeoutBeforeRetry = 10 * time.Second

	ch := make(chan model.SyncStatus)
	go func() {
	outer:
		for {
			stream, err := c.SyncStatuses(ctx, new(emptypb.Empty))
			if err == nil {
				for {
					syncStatus, err := stream.Recv()
					if err != nil {
						break
					}
					ch <- model.SyncStatus{UpdatedAt: syncStatus.GetUpdatedAt().AsTime()}
				}
			} else {
				logger.Error(ctx, "Attempt to make grpc call failed:", err)
			}

			select {
			case <-ctx.Done():
				break outer
			case <-time.After(timeoutBeforeRetry):
			}
		}
	}()
	return ch
}
