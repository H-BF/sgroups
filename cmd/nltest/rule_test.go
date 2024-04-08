package main

import (
	"context"
	"net"
	"testing"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNl2rule(t *testing.T) {
	cases := []struct {
		nlRule   *nft.Rule
		sets     map[string]*nft.Set
		setEls   map[string][]nft.SetElement
		wantRule nftablesRule
		err      bool
	}{
		// ip saddr 192.168.10.11 counter packets 5 bytes 1000 drop
		{
			nlRule:   createNlRuleWithAddrCmp(OffsetV4Saddr, []byte{192, 168, 10, 11}, expr.VerdictDrop),
			wantRule: createWantedRule([]string{"192.168.10.11"}, nil, nil, nil, "drop"),
		},

		// ip saddr adc6:ef93::1 counter packets 5 bytes 1000 jump somewhere
		{
			nlRule: createNlRuleWithAddrCmp(OffsetV6Saddr,
				[]byte{173, 198, 239, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, expr.VerdictJump),
			wantRule: createWantedRule([]string{"adc6:ef93::1"}, nil, nil, nil, "policy"),
		},

		// ip daddr @NetIPv4-sg-dmy1 counter packets 5 bytes 1000 accept
		{
			nlRule: createNlRuleWithAddrLookup(OffsetV4Daddr, "NetIPv4-sg-dmy1", expr.VerdictAccept),
			sets: map[string]*nft.Set{
				"NetIPv4-sg-dmy1": {
					Name:      "NetIPv4-sg-dmy1",
					Anonymous: false,
				},
			},
			setEls: map[string][]nft.SetElement{
				"NetIPv4-sg-dmy1": {
					{
						Key:         []byte{10, 10, 0, 0},
						IntervalEnd: true,
					},
					{
						Key:         []byte{10, 10, 1, 0},
						IntervalEnd: false,
					},
				},
			},
			wantRule: createWantedRule(nil, []string{"@NetIPv4-sg-dmy1"}, nil, nil, "accept"),
		},

		// tcp dport 20-40 counter packets 5 bytes 1000 accept
		{
			nlRule: createNlRuleWithPortsCmp(
				OffsetDport,
				[]expr.Any{
					&expr.Cmp{
						Op:   expr.CmpOpGte,
						Data: []byte{0, 20},
					},
					&expr.Cmp{
						Op:   expr.CmpOpLte,
						Data: []byte{0, 40},
					}},
				expr.VerdictAccept),
			wantRule: createWantedRule(nil, nil, nil, []string{"20", "40"}, "accept"),
		},

		// tcp sport { 1, 2, 3, 1000 } counter packets 5 bytes 1000 drop
		{
			nlRule: createNlRuleWithPortsLookup(OffsetSport, "__set0", expr.VerdictDrop),
			// non interval set like nft cli do it
			sets: map[string]*nft.Set{
				"__set0": {
					Name:      "__set0",
					Anonymous: true,
				},
			},
			setEls: map[string][]nft.SetElement{
				"__set0": {
					{
						Key: []byte{0, 1},
					},
					{
						Key: []byte{0, 2},
					},
					{
						Key: []byte{0, 3},
					},
					{
						Key: []byte{3, 232},
					},
				},
			},
			wantRule: createWantedRule(nil, nil, []string{"1", "2", "3", "1000"}, nil, "drop"),
		},

		// tcp sport { 80, 90 } counter packets 5 bytes 1000 accept
		{
			nlRule: createNlRuleWithPortsLookup(OffsetSport, "__set1", expr.VerdictAccept),
			// interval set like sgroups do it
			sets: map[string]*nft.Set{
				"__set1": {
					Name:      "__set1",
					Anonymous: true,
					Interval:  true,
				},
			},
			setEls: map[string][]nft.SetElement{
				"__set1": {
					{
						Key:         []byte{0, 91},
						IntervalEnd: true,
					},
					{
						Key: []byte{0, 90},
					},
					{
						Key:         []byte{0, 81},
						IntervalEnd: true,
					},
					{
						Key: []byte{0, 80},
					},
				},
			},
			wantRule: createWantedRule(nil, nil, []string{"80", "90"}, nil, "accept"),
		},

		// meta nftrace set 1 icmp type { 100 } counter packets 5 bytes 1000 log level debug flags ip options drop
		{
			nlRule: createNlRuleWithNftraceAndIcmp("__set2", expr.VerdictDrop),
			sets: map[string]*nft.Set{
				"__set2": {
					Name:      "__set2",
					Anonymous: true,
					Constant:  true,
				},
			},
			setEls: map[string][]nft.SetElement{
				"__set2": {
					{
						Key: []byte{100},
					},
				},
			},
			wantRule: createWantedRule(nil, nil, nil, nil, "drop"),
		},
	}

	for i, c := range cases {
		got, err := nl2rule(context.Background(), c.nlRule, c.sets, c.setEls)
		if !c.err {
			require.NoErrorf(t, err, "TestNl2rule: testcase %d failed", i)
		} else {
			require.Errorf(t, err, "TestNl2rule: testcase %d should fail", i)
		}
		require.Equalf(t, c.wantRule, got, "TestNl2rule: testcase %d got rule differs from wanted", i)
	}
}

func createNlRule(exprs []expr.Any) *nft.Rule {
	t := &nft.Table{
		Name:   "main",
		Use:    0,
		Flags:  0,
		Family: nft.TableFamilyINet,
	}
	return &nft.Rule{
		Table: t,
		Chain: &nft.Chain{
			Name:     "main-chain",
			Table:    t,
			Hooknum:  nil,
			Priority: nil,
			Type:     nft.ChainTypeFilter,
			Policy:   nil,
			Handle:   0,
		},
		Position: 0,
		Handle:   0,
		Flags:    0,
		Exprs:    exprs,
		UserData: nil,
	}
}

func createNlRuleWithAddrCmp(addrOffset uint32, ip net.IP, verdict expr.VerdictKind) *nft.Rule {
	metaCmp := expr.Cmp{
		Op:   expr.CmpOpEq,
		Data: []byte{unix.NFPROTO_IPV4},
	}
	payload := expr.Payload{
		OperationType: expr.PayloadLoad,
		Base:          expr.PayloadBaseNetworkHeader,
		Offset:        addrOffset,
		Len:           0, // TODO
	}
	switch addrOffset {
	case OffsetV4Saddr:
		metaCmp.Data = []byte{unix.NFPROTO_IPV4}
	case OffsetV4Daddr:
		metaCmp.Data = []byte{unix.NFPROTO_IPV4}
	case OffsetV6Saddr:
		metaCmp.Data = []byte{unix.NFPROTO_IPV6}
	case OffsetV6Daddr:
		metaCmp.Data = []byte{unix.NFPROTO_IPV6}

	}
	return createNlRule([]expr.Any{
		&expr.Meta{
			Key: expr.MetaKeyNFPROTO,
		},
		&metaCmp,
		&payload,
		&expr.Cmp{
			Op:   expr.CmpOpEq,
			Data: ip,
		},
		createCounter(1000, 5),
		&expr.Verdict{
			Kind: verdict,
		},
	})
}

func createNlRuleWithAddrLookup(addrOffset uint32, setName string, verdict expr.VerdictKind) *nft.Rule {
	metaCmp := expr.Cmp{
		Op: expr.CmpOpEq,
	}
	payload := expr.Payload{
		OperationType: expr.PayloadLoad,
		Base:          expr.PayloadBaseNetworkHeader,
		Offset:        addrOffset,
		Len:           0, // TODO
	}
	switch addrOffset {
	case OffsetV4Saddr:
		metaCmp.Data = []byte{unix.NFPROTO_IPV4}
	case OffsetV4Daddr:
		metaCmp.Data = []byte{unix.NFPROTO_IPV4}
	case OffsetV6Saddr:
		metaCmp.Data = []byte{unix.NFPROTO_IPV6}
	case OffsetV6Daddr:
		metaCmp.Data = []byte{unix.NFPROTO_IPV6}
	}
	return createNlRule([]expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO},
		&metaCmp,
		&payload,
		&expr.Lookup{SetName: "NetIPv4-sg-dmy1"},
		createCounter(1000, 5),
		&expr.Verdict{Kind: verdict},
	})
}

func createNlRuleWithPortsCmp(portOffset uint32, portCmps []expr.Any, verdict expr.VerdictKind) *nft.Rule {
	rule := createNlRule([]expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO},
		&expr.Cmp{
			Op:   expr.CmpOpEq,
			Data: []byte{unix.IPPROTO_TCP},
		},
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			Base:          expr.PayloadBaseTransportHeader,
			Offset:        portOffset,
			Len:           2,
		},
	})
	rule.Exprs = append(rule.Exprs, portCmps...)
	rule.Exprs = append(rule.Exprs,
		createCounter(1000, 5),
		&expr.Verdict{Kind: verdict})
	return rule
}

func createNlRuleWithPortsLookup(portOffset uint32, setName string, verdict expr.VerdictKind) *nft.Rule {
	return createNlRule([]expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO},
		&expr.Cmp{
			Op:   expr.CmpOpEq,
			Data: []byte{unix.IPPROTO_TCP},
		},
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			Base:          expr.PayloadBaseTransportHeader,
			Offset:        portOffset,
			Len:           2,
		},
		&expr.Lookup{SetName: setName},
		createCounter(1000, 5),
		&expr.Verdict{Kind: verdict},
	})
}

func createNlRuleWithNftraceAndIcmp(setName string, verdict expr.VerdictKind) *nft.Rule {
	return createNlRule([]expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     []byte{1},
		},
		&expr.Meta{
			Key:            expr.MetaKeyNFTRACE,
			SourceRegister: true,
			Register:       1,
		},
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{1},
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       0,
			Len:          1,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        setName,
		},
		createCounter(1000, 5),
		&expr.Log{
			Level: expr.LogLevelDebug,
			Flags: expr.LogFlagsIPOpt,
			Key:   96,
			Data:  []byte{},
		},
		&expr.Verdict{Kind: verdict},
	})
}

func createCounter(bytes, packets uint64) *expr.Counter {
	return &expr.Counter{
		Bytes:   bytes,
		Packets: packets,
	}
}

func createWantedRule(aSrc, aDest, pSrc, pDest []string, action string) nftablesRule {
	return nftablesRule{
		Chain:   "main-chain",
		Table:   "main",
		Family:  "inet",
		Comment: "empty",
		Action:  action,
		Handle:  "0",
		Interfaces: struct {
			Input  []string
			Output []string
		}{},
		Addresses: struct {
			Source      []string
			Destination []string
		}{
			Source:      aSrc,
			Destination: aDest,
		},
		Ports: struct {
			Source      []string
			Destination []string
		}{
			Source:      pSrc,
			Destination: pDest,
		},
		Counter: &Counter{
			Bytes:   1000,
			Packets: 5,
		},
	}
}
