package metrics

import (
	"strconv"
	"strings"

	dkt "github.com/H-BF/sgroups/internal/dict"
	"github.com/H-BF/sgroups/internal/nftables/conf"
	"github.com/H-BF/sgroups/internal/nftables/conf/view"
	hlp "github.com/H-BF/sgroups/internal/nftables/helpers"

	nftlib "github.com/google/nftables"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

func state2MetricsView(cnf conf.StateOfNFTables) (mets []prometheus.Metric, err error) {
	var excludedTables dkt.HSet[conf.NfTableKey]
	cnf.Tables.Iterate(func(tKey conf.NfTableKey, t *nftlib.Table) bool {
		if t.Flags&unix.NFT_TABLE_F_DORMANT != 0 {
			excludedTables.Put(tKey)
			return true
		}
		family := hlp.TableFamily2S(t.Family)
		chains := cnf.Chains.At(tKey)
		metric, e := prometheus.NewConstMetric(tableChainsDesc,
			prometheus.GaugeValue,
			float64(chains.Len()),
			t.Name,
			family,
		)
		err = e
		mets = append(mets, metric)
		return e == nil
	})
	if err != nil {
		return nil, err
	}

	cnf.Objects.Iterate(func(tKey conf.NfTableKey, tObjs []nftlib.Obj) bool {
		if excludedTables.Contains(tKey) {
			return true
		}
		family := hlp.TableFamily2S(tKey.TableFamily)
		for i := range tObjs {
			if namedCounter, _ := tObjs[i].(*nftlib.CounterObj); namedCounter != nil {
				metric, e := prometheus.NewConstMetric(counterBytesDesc,
					prometheus.CounterValue,
					float64(namedCounter.Bytes),
					namedCounter.Name,
					tKey.Name,
					family,
				)
				if e != nil {
					err = e
					return false
				}
				mets = append(mets, metric)

				metric, e = prometheus.NewConstMetric(counterPacketsDesc,
					prometheus.CounterValue,
					float64(namedCounter.Packets),
					namedCounter.Name,
					tKey.Name,
					family,
				)
				if e != nil {
					err = e
					return false
				}
				mets = append(mets, metric)
			}
		}
		return true
	})
	if err != nil {
		return nil, err
	}

	cnf.Chains.Iterate(func(tKey conf.NfTableKey, tChains dkt.HDict[conf.NfChainKey, conf.NfChain]) bool {
		if excludedTables.Contains(tKey) {
			return true
		}
		tChains.Iterate(func(cKey conf.NfChainKey, c conf.NfChain) bool {
			for _, rule := range c.Rules {
				ruleView, e := view.NewRuleView(rule, cnf.Sets.At(tKey))
				if e != nil {
					err = e
					return false
				}
				var m []prometheus.Metric
				if m, e = metricsFromRule(ruleView); e != nil {
					err = e
					return false
				}
				mets = append(mets, m...)
			}
			metric, e := prometheus.NewConstMetric(chainRulesDesc,
				prometheus.GaugeValue,
				float64(len(c.Rules)),
				c.Name,
				hlp.TableFamily2S(c.Table.Family),
				c.Table.Name,
				strconv.FormatUint(c.Handle, 10),
			)
			if e == nil {
				mets = append(mets, metric)
			}
			err = e
			return e == nil
		})
		return err == nil
	})
	if err != nil {
		mets = nil
	}
	return mets, err
}

func metricsFromRule(ruleView *view.RuleView) (mets []prometheus.Metric, err error) {
	arrayToTag := func(values []string) string {
		if len(values) == 0 {
			return "any"
		}
		return strings.Join(values, ",")
	}
	if ruleView.Counter != nil {
		inputInterfaces := arrayToTag(ruleView.Interfaces.Input)
		outputInterfaces := arrayToTag(ruleView.Interfaces.Output)
		sourceAddresses := arrayToTag(ruleView.Addresses.Source)
		destinationAddresses := arrayToTag(ruleView.Addresses.Destination)
		sourcePorts := arrayToTag(ruleView.Ports.Source)
		destinationPorts := arrayToTag(ruleView.Ports.Destination)

		metric, err := prometheus.NewConstMetric(
			ruleBytesDesc,
			prometheus.CounterValue,
			ruleView.Counter.Bytes,
			ruleView.Chain,
			ruleView.Family,
			ruleView.Table,
			inputInterfaces,
			outputInterfaces,
			sourceAddresses,
			destinationAddresses,
			sourcePorts,
			destinationPorts,
			ruleView.Comment,
			ruleView.Action,
			ruleView.Handle,
		)
		if err != nil {
			return nil, err
		}
		mets = append(mets, metric)
		metric, err = prometheus.NewConstMetric(
			rulePacketsDesc,
			prometheus.CounterValue,
			ruleView.Counter.Packets,
			ruleView.Chain,
			ruleView.Family,
			ruleView.Table,
			inputInterfaces,
			outputInterfaces,
			sourceAddresses,
			destinationAddresses,
			sourcePorts,
			destinationPorts,
			ruleView.Comment,
			ruleView.Action,
			ruleView.Handle,
		)
		if err != nil {
			return nil, err
		}
		mets = append(mets, metric)
	}
	return mets, nil
}
