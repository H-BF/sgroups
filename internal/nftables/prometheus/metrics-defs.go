package metrics

import (
	prom "github.com/prometheus/client_golang/prometheus"
)

var (
	upDesc = prom.NewDesc(
		"nftables_up",
		"'1' if reading the nft output was successful, '0' otherwise",
		nil,
		nil,
	)
	counterBytesDesc = prom.NewDesc(
		"nftables_counter_bytes",
		"bytes, matched by counter",
		[]string{
			"name",
			"table",
			"family",
		},
		nil,
	)
	counterPacketsDesc = prom.NewDesc(
		"nftables_counter_packets",
		"packets, matched by counter",
		[]string{
			"name",
			"table",
			"family",
		},
		nil,
	)
	tableChainsDesc = prom.NewDesc(
		"nftables_table_chains",
		"count chains in table",
		[]string{
			"name",
			"family",
		},
		nil,
	)
	chainRulesDesc = prom.NewDesc(
		"nftables_chain_rules",
		"count rules in chain",
		[]string{
			"name",
			"family",
			"table",
			"handle",
		},
		nil,
	)
	ruleBytesDesc = prom.NewDesc(
		"nftables_rule_bytes",
		"bytes, matched by rule per rule comment",
		[]string{
			"chain",
			"family",
			"table",
			"input_interfaces",
			"output_interfaces",
			"source_addresses",
			"destination_addresses",
			"source_ports",
			"destination_ports",
			"comment",
			"action",
			"handle",
		},
		nil,
	)
	rulePacketsDesc = prom.NewDesc(
		"nftables_rule_packets",
		"packets, matched by rule per rule comment",
		[]string{
			"chain",
			"family",
			"table",
			"input_interfaces",
			"output_interfaces",
			"source_addresses",
			"destination_addresses",
			"source_ports",
			"destination_ports",
			"comment",
			"action",
			"handle",
		},
		nil,
	)
)
