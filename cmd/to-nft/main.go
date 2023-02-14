//go:build linux
// +build linux

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
	"github.com/H-BF/sgroups/pkg/nl"

	"github.com/H-BF/corlib/logger"
	gs "github.com/H-BF/corlib/pkg/patterns/graceful-shutdown"
	"github.com/pkg/errors"
	"go.uber.org/zap"
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
		config.WithDefValue{Key: AppLoggerLevel, Val: "DEBUG"},
		config.WithDefValue{Key: AppGracefulShutdown, Val: 10 * time.Second},
		config.WithDefValue{Key: NetNS, Val: ""},
		config.WithDefValue{Key: ServicesDefDialDuration, Val: 10 * time.Second},
		config.WithDefValue{Key: SGroupsAddress, Val: "tcp://127.0.0.1:9000"},
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

func runNftJob(ctx context.Context) error {
	var (
		err       error
		sgClient  SGClient
		nlWatcher nl.NetlinkWatcher
		nftProc   nft.NfTablesProcessor
	)

	if sgClient, err = NewSGClient(ctx); err != nil {
		return err
	}
	defer sgClient.CloseConn() //nolint:errcheck

	netNs, _ := NetNS.Value(ctx)
	netWathOpts := []nl.WatcherOption{
		nl.WithAgeOfMatutity{Age: 10 * time.Second},
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
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case msgs, ok := <-stm:
			if !ok {
				err = nl.ErrUnexpectedlyStopped
				break loop
			}
			for _, m := range msgs {
				if e, ok := m.(nl.ErrMsg); ok {
					if errors.Is(e.Err, nl.ErrUnexpectedlyStopped) {
						err = e
						break loop
					}
					logger.ErrorKV(ctx, "net-watcher", "error", e)
				}
			}
			if conf.UpdFromWatcher(msgs...) == 0 {
				continue
			}
			logger.Infof(ctx, "net-conf has updated then it will apply")
			if err = nftProc.ApplyConf(ctx, conf); err != nil {
				logger.Errorf(ctx, "net-conf din`t apply")
				break loop
			}
			logger.Infof(ctx, "net-conf applied")
		}
	}
	return err
}
