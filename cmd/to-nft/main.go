//go:build linux
// +build linux

package main

import (
	"context"
	"flag"
	"time"

	"github.com/H-BF/corlib/logger"
	. "github.com/H-BF/sgroups/cmd/to-nft/internal" //nolint:revive
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft"
	"github.com/H-BF/sgroups/internal/app"
	"github.com/H-BF/sgroups/internal/config"
	"github.com/H-BF/sgroups/pkg/nl"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func main() {
	flag.Parse()
	SetupContext()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= HELLO =-")

	err := config.InitGlobalConfig(
		config.WithAcceptEnvironment{EnvPrefix: "NFT"},
		config.WithSourceFile{FileName: ConfigFile},
		config.WithDefValue{Key: AppLoggerLevel, Val: "DEBUG"},
		config.WithDefValue{Key: AppGracefulShutdown, Val: 10 * time.Second},
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
			select {
			case <-time.NewTimer(gracefulDuration).C:
			case jobErr = <-errc:
			}
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

	nlWatcher, err = nl.NewNetlinkWatcher(nl.WithAgeOfMatutity{Age: 10 * time.Second})
	if err != nil {
		return errors.WithMessage(err, "create net-watcher")
	}
	defer nlWatcher.Close()

	nftProc = nft.NewNfTablesProcessor(ctx, sgClient)
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
