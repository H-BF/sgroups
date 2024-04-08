package main

import (
	"context"
	"net/http"
	"time"

	"github.com/H-BF/corlib/logger"
	"github.com/google/nftables"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

func main() {
	logger.SetLevel(zap.DebugLevel)
	reg := prometheus.NewPedanticRegistry()
	//reg.MustRegister(
	//	collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	//	collectors.NewGoCollector(),
	//)

	ctx := context.Background()

	conn, err := nftables.New()
	if err != nil {
		logger.Fatalf(ctx, "nl conn err: %v", err)
	}
	prometheus.WrapRegistererWithPrefix("", reg).MustRegister(&nftCollector{ctx, conn})

	logger.Info(ctx, "starting on :9630/")
	http.Handle("/", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	server := http.Server{
		Addr:              ":9630",
		ReadHeaderTimeout: 1 * time.Minute,
	}
	logger.Fatal(ctx, server.ListenAndServe())
}
