//go:build linux
// +build linux

package main

import (
	"flag"
	"time"

	"github.com/H-BF/corlib/logger"
	. "github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/internal/app"
	"github.com/H-BF/sgroups/internal/config"
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
		logger.Fatal(ctx, errors.WithMessage(err, "when setup logger"))
	}
	//ServicesDefDialDuration.Value(ctx, ServicesDefDialDuration.OptSink(func(d time.Duration) error {return nil}))
	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}
