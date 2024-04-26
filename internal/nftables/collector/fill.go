package metrics

import (
	"strconv"
	"strings"

	dkt "github.com/H-BF/sgroups/internal/dict"
	"github.com/H-BF/sgroups/internal/nftables/conf"
	hlp "github.com/H-BF/sgroups/internal/nftables/helpers"
	"github.com/H-BF/sgroups/internal/nftables/parser"

	"github.com/H-BF/corlib/logger"
	nftlib "github.com/google/nftables"
	"github.com/prometheus/client_golang/prometheus"
)

func fillFromState(cnf conf.StateOfNFTables, mets *[]prometheus.Metric, log *logger.TypeOfLogger) {
	cnf.Tables.Iterate(func(tKey conf.NfTableKey, t *nftlib.Table) bool {
		family := hlp.TableFamily2S(t.Family)
		var tableChains int

		if chains, ok := cnf.Chains.Get(tKey); ok {
			tableChains = chains.Len()
		}
		if metric, err := prometheus.NewConstMetric(tableChainsDesc,
			prometheus.GaugeValue,
			float64(tableChains),
			t.Name,
			family); err == nil {
			*mets = append(*mets, metric)
		}
		return true
	})

	cnf.Objects.Iterate(func(tKey conf.NfTableKey, tObjs []nftlib.Obj) bool {
		for i := range tObjs {
			if namedCounter, ok := tObjs[i].(*nftlib.CounterObj); ok {
				family := hlp.TableFamily2S(namedCounter.Table.Family)
				if metric, err := prometheus.NewConstMetric(counterBytesDesc,
					prometheus.CounterValue,
					float64(namedCounter.Bytes),
					namedCounter.Name,
					namedCounter.Table.Name,
					family); err == nil {
					*mets = append(*mets, metric)
				}
				if metric, err := prometheus.NewConstMetric(counterPacketsDesc,
					prometheus.CounterValue,
					float64(namedCounter.Packets),
					namedCounter.Name,
					namedCounter.Table.Name,
					family); err == nil {
					*mets = append(*mets, metric)
				}
			}
		}
		return true
	})

	cnf.Chains.Iterate(func(tKey conf.NfTableKey, tChains dkt.HDict[conf.NfChainKey, conf.NfChain]) bool {
		tChains.Iterate(func(cKey conf.NfChainKey, c conf.NfChain) bool {
			for _, rule := range c.Rules {
				if parsedRule, err := parser.From(rule, cnf.Sets.At(tKey), log); err == nil {
					*mets = append(*mets, metricsFromRule(parsedRule)...)
				}
			}

			if metric, err := prometheus.NewConstMetric(chainRulesDesc,
				prometheus.GaugeValue,
				float64(len(c.Rules)),
				c.Name,
				hlp.TableFamily2S(c.Table.Family),
				c.Table.Name,
				strconv.FormatUint(c.Handle, 10),
			); err == nil {
				*mets = append(*mets, metric)
			}
			return true
		})
		return true
	})
}

func metricsFromRule(parsedRule *parser.Rule) (mets []prometheus.Metric) {
	if parsedRule.Counter != nil {
		inputInterfaces := arrayToTag(parsedRule.Interfaces.Input)
		outputInterfaces := arrayToTag(parsedRule.Interfaces.Output)
		sourceAddresses := arrayToTag(parsedRule.Addresses.Source)
		destinationAddresses := arrayToTag(parsedRule.Addresses.Destination)
		sourcePorts := arrayToTag(parsedRule.Ports.Source)
		destinationPorts := arrayToTag(parsedRule.Ports.Destination)

		if metric, err := prometheus.NewConstMetric(
			ruleBytesDesc,
			prometheus.CounterValue,
			parsedRule.Counter.Bytes,
			parsedRule.Chain,
			parsedRule.Family,
			parsedRule.Table,
			inputInterfaces,
			outputInterfaces,
			sourceAddresses,
			destinationAddresses,
			sourcePorts,
			destinationPorts,
			parsedRule.Comment,
			parsedRule.Action,
			parsedRule.Handle,
		); err == nil {
			mets = append(mets, metric)
		}
		if metric, err := prometheus.NewConstMetric(
			rulePacketsDesc,
			prometheus.CounterValue,
			parsedRule.Counter.Packets,
			parsedRule.Chain,
			parsedRule.Family,
			parsedRule.Table,
			inputInterfaces,
			outputInterfaces,
			sourceAddresses,
			destinationAddresses,
			sourcePorts,
			destinationPorts,
			parsedRule.Comment,
			parsedRule.Action,
			parsedRule.Handle,
		); err == nil {
			mets = append(mets, metric)
		}
	}
	return mets
}

func arrayToTag(values []string) string {
	if len(values) == 0 {
		return "any"
	}
	return strings.Join(values, ",")
}
