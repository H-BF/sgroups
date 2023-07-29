package main

import (
	"context"
	"flag"
	"os"
	"reflect"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		exitOnSuffess bool
		sgClient      SGClient
		nlWatcher     nl.NetlinkWatcher
		nftProc       nft.NfTablesProcessor
	)
	if exitOnSuffess, err = ExitOnSuccess.Value(ctx); err != nil {
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
	nftProc = nft.NewNfTablesProcessor(sgClient, opts...)
	defer nftProc.Close()

	var conf nft.NetConf
	conf.Init()
	stm := nlWatcher.Stream()

	sel := []reflect.SelectCase{
		{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ctx.Done()),
		},
		{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(stm),
		},
	}
	if syncCheckInterval, _ := SGroupsSyncStatusInterval.Value(ctx); syncCheckInterval >= time.Second {
		tc := time.NewTicker(syncCheckInterval)
		defer tc.Stop()
		sel = append(sel, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(tc.C),
		})
	} else {
		return errors.Errorf("bad config value '%s': '%s'",
			SGroupsSyncStatusInterval, syncCheckInterval)
	}
	var syncStatus model.SyncStatus
	var appliedCount int
loop0:
	for needApply := false; ; needApply = false {
		chosen, val, succ := reflect.Select(sel)
		switch chosen {
		case 0: //Done() from ctx
			break loop0
		case 1: //messages from NetWatcher
			if !succ {
				err = nl.ErrUnexpectedlyStopped
				break loop0
			}
			msgs := val.Interface().([]nl.WatcherMsg)
			for _, m := range msgs {
				if e, ok := m.(nl.ErrMsg); ok {
					if errors.Is(e.Err, nl.ErrUnexpectedlyStopped) {
						err = e
						break loop0
					}
					logger.ErrorKV(ctx, "net-watcher", "error", e)
				}
			}
			needApply = conf.UpdFromWatcher(msgs...) != 0 || appliedCount == 0
			if needApply {
				var st model.SyncStatus
				if st, err = getSyncStatus(ctx, sgClient); err != nil {
					break loop0
				}
				syncStatus = st
			}
		case 2: //backend watcher from ticker
			if appliedCount != 0 {
				var st model.SyncStatus
				if st, err = getSyncStatus(ctx, sgClient); err != nil {
					break loop0
				}
				needApply = !syncStatus.UpdatedAt.Equal(st.UpdatedAt)
				syncStatus = st
			}
		}
		if needApply {
			appliedCount++
			logger.Infof(ctx, "net-conf will apply now")
			if err = nftProc.ApplyConf(ctx, conf); err != nil {
				logger.Errorf(ctx, "net-conf din`t apply")
				break
			}
			logger.Infof(ctx, "net-conf applied")
			if exitOnSuffess {
				break loop0
			}
		}
	}
	return err
}

func getSyncStatus(ctx context.Context, c SGClient) (model.SyncStatus, error) {
	var ret model.SyncStatus
	resp, err := c.SyncStatus(ctx, new(emptypb.Empty))
	if err == nil {
		ret.UpdatedAt = resp.GetUpdatedAt().AsTime()
	} else if e := errors.Cause(err); status.Code(e) == codes.NotFound {
		err = nil
	}
	return ret, err
}
