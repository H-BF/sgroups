package main

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/H-BF/corlib/logger"
	"github.com/google/nftables"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type nftCollector struct {
	ctx  context.Context
	conn *nftables.Conn
	dump string
}

func (c *nftCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- upDesc
	ch <- counterBytesDesc
	ch <- counterPacketsDesc
	ch <- tableChainsDesc
	ch <- chainRulesDesc
	ch <- ruleBytesDesc
	ch <- rulePacketsDesc
}

func (c *nftCollector) Collect(ch chan<- prometheus.Metric) {
	if err := collect(c.ctx, ch, c.conn, c.dump); err != nil {
		logger.Errorf(c.ctx, "failed get metrics from netlink: %v", err)
		ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, 0)
	} else {
		ch <- prometheus.MustNewConstMetric(upDesc, prometheus.GaugeValue, 1)
	}
}

func collect(ctx context.Context, ch chan<- prometheus.Metric, conn *nftables.Conn, dump string) error {
	tables, err := conn.ListTables()
	if err != nil {
		return err
	}

	chains, err := conn.ListChains()
	if err != nil {
		return err
	}

	rules, err := conn.GetAllRules()
	if err != nil {
		return err
	}

	// for case when problems with collecting :'
	if len(dump) != 0 {
		file, err := os.OpenFile(dump, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return err
		}
		defer func() {
			_ = file.Close()
		}()
		ctx = logger.ToContext(ctx, logger.NewWithSink(zap.NewAtomicLevelAt(zap.DebugLevel), file))
	}

	logger.Debug(ctx, "collect started")

	for i := range tables {
		t := tables[i]
		family := family2str(t.Family)
		tObjs, err := conn.GetObjects(t)
		if err != nil {
			logger.Debugf(ctx, "get table objects err: %v", err)
		} else {
			for i := range tObjs {
				namedCounter, ok := tObjs[i].(*nftables.CounterObj)
				if !ok {
					continue
				}
				ch <- prometheus.MustNewConstMetric(
					counterBytesDesc,
					prometheus.CounterValue,
					float64(namedCounter.Bytes),
					namedCounter.Name,
					namedCounter.Table.Name,
					family,
				)
				ch <- prometheus.MustNewConstMetric(
					counterPacketsDesc,
					prometheus.CounterValue,
					float64(namedCounter.Packets),
					namedCounter.Name,
					namedCounter.Table.Name,
					family,
				)
			}
		}

		sets, err := conn.GetSets(t)
		if err != nil {
			logger.Debugf(ctx, "get sets [table: %s] err: %v", t.Name, err)
			continue
		}

		setMapping := make(map[string]*nftables.Set)
		setElements := make(map[string][]nftables.SetElement)
		for _, set := range sets {
			elements, err := conn.GetSetElements(set)
			if err != nil {
				logger.Debugf(ctx, "get set elements [table:%s, set:%s] err: %v", t.Name, set.Name, err)
				continue
			}
			logger.Debugf(ctx, "Set{%+v} elements: %+v", set, elements)
			setElements[set.Name] = elements
			setMapping[set.Name] = set
		}

		tableChains := 0
		for i := range chains {
			c := chains[i]
			if c.Table.Name == t.Name && c.Table.Family == t.Family {
				tableChains++

				chainRules := 0
				for _, rule := range rules {
					if rule.Table.Name == t.Name && rule.Table.Family == t.Family && rule.Chain.Name == c.Name {
						chainRules++

						r, err := nl2rule(ctx, rule, setMapping, setElements)
						if err != nil {
							logger.Debugf(ctx, "nl rule [table:%s, chain:%s] conversion err: %v",
								t.Name, c.Name, err)
							continue
						}

						if r.Counter != nil {
							r.collect(ch)
						}
					}
				}

				ch <- prometheus.MustNewConstMetric(
					chainRulesDesc,
					prometheus.GaugeValue,
					float64(chainRules),
					c.Name,
					family,
					t.Name,
					strconv.FormatUint(c.Handle, 10),
				)
			}
		}
		ch <- prometheus.MustNewConstMetric(
			tableChainsDesc,
			prometheus.GaugeValue,
			float64(tableChains),
			t.Name,
			family,
		)
	}

	logger.Debug(ctx, "collect finished")

	return nil
}

func arrayToTag(values []string) string {
	if len(values) == 0 {
		return "any"
	}
	return strings.Join(values, ",")
}
