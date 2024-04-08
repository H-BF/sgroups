package main

import (
	"context"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"strconv"

	"github.com/H-BF/corlib/logger"
	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/pkg/errors"
)

// nftablesRule - chain rule
type nftablesRule struct {
	Chain      string
	Table      string
	Family     string
	Comment    string
	Action     string
	Handle     string
	Interfaces struct {
		Input  []string
		Output []string
	}
	Addresses struct {
		Source      []string
		Destination []string
	}
	Ports struct {
		Source      []string
		Destination []string
	}
	*Counter
}

type Counter struct {
	Bytes   float64
	Packets float64
}

func nl2rule(ctx context.Context, nlRule *nft.Rule, setMapping map[string]*nft.Set, setElements map[string][]nft.SetElement) (nftablesRule, error) {
	formatRule(nlRule)

	r := nftablesRule{
		Chain:   nlRule.Chain.Name,
		Family:  family2str(nlRule.Table.Family),
		Table:   nlRule.Table.Name,
		Comment: "empty",
		Action:  "policy",
		Handle:  strconv.FormatUint(nlRule.Handle, 10),
	}

	parserCtx := newParserCtx(ctx, &r, setMapping, setElements)

	parserCtx.debug = true // TODO: turn off me

	for _, e := range nlRule.Exprs {
		switch v := e.(type) {
		case *expr.Counter:
			if r.Counter != nil {
				return r, errors.New("counter already exists")
			}
			r.Counter = new(Counter)
			r.Counter.Bytes = float64(v.Bytes)
			r.Counter.Packets = float64(v.Packets)
		case *expr.Lookup:
			parserCtx.parseLookup(v)
		case *expr.Cmp:
			parserCtx.parseCmp(v)
		case *expr.Payload:
			parserCtx.parsePayload(v)
		case *expr.Verdict:
			parserCtx.parseVerdict(v)
		case *expr.Meta:
			parserCtx.parseMeta(v)
		default:
			logger.Debugf(ctx, "*** Any{Type: %T}", e)
		}
	}
	return r, nil
}

func (r *nftablesRule) collect(ch chan<- prometheus.Metric) {
	inputInterfaces := arrayToTag(r.Interfaces.Input)
	outputInterfaces := arrayToTag(r.Interfaces.Output)
	sourceAddresses := arrayToTag(r.Addresses.Source)
	destinationAddresses := arrayToTag(r.Addresses.Destination)
	sourcePorts := arrayToTag(r.Ports.Source)
	destinationPorts := arrayToTag(r.Ports.Destination)

	ch <- prometheus.MustNewConstMetric(
		ruleBytesDesc,
		prometheus.CounterValue,
		r.Counter.Bytes,
		r.Chain,
		r.Family,
		r.Table,
		inputInterfaces,
		outputInterfaces,
		sourceAddresses,
		destinationAddresses,
		sourcePorts,
		destinationPorts,
		r.Comment,
		r.Action,
		r.Handle,
	)

	ch <- prometheus.MustNewConstMetric(
		rulePacketsDesc,
		prometheus.CounterValue,
		r.Counter.Packets,
		r.Chain,
		r.Family,
		r.Table,
		inputInterfaces,
		outputInterfaces,
		sourceAddresses,
		destinationAddresses,
		sourcePorts,
		destinationPorts,
		r.Comment,
		r.Action,
		r.Handle,
	)
}

func (r *nftablesRule) String() string {
	return fmt.Sprintf("Rule{Chain:%s, Table:%s, Family:%s, Comment:%s, Action:%s, Handle: %s, Interfaces:{Input:%v, Output:%v}, Addresses:{Source:%v, Destination:%v}, Ports:{Source:%v, Destination:%v}, Counter:%v}",
		r.Chain, r.Table, r.Family, r.Comment, r.Action, r.Handle, r.Interfaces.Input, r.Interfaces.Output, r.Addresses.Source, r.Addresses.Destination, r.Ports.Source, r.Ports.Destination, r.Counter)
}

func formatRule(r *nft.Rule) {
	fmt.Printf("    rule: Position=%d, Handle=%d, Flags=0x%X, UserData=%v, Exprs=[",
		r.Position, r.Handle, r.Flags, r.UserData)

	for _, e := range r.Exprs {
		switch v := e.(type) {
		case *expr.Counter:
			fmt.Printf(" Counter{Bytes: %d, Packets: %d},", v.Bytes, v.Packets)
		default:
			fmt.Printf(" Any{Type: %T, value: %+v},", e, e)
		}
	}
	fmt.Println("]")
}
