package view

import (
	"net"
	"testing"

	dkt "github.com/H-BF/sgroups/internal/dict"
	"github.com/H-BF/sgroups/internal/nftables/conf"
	hlp "github.com/H-BF/sgroups/internal/nftables/helpers"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

var (
	sgDmySet = map[string]conf.NfSet{
		"NetIPv4-sg-dmy1": {
			Set: &nft.Set{
				Name:      "NetIPv4-sg-dmy1",
				Anonymous: false,
			},
			Elements: []nft.SetElement{
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
	}
)

func TestFrom(t *testing.T) {
	cases := []struct {
		nlRule   *nft.Rule
		setsConf dkt.HDict[string, conf.NfSet]
		want     *RuleView
		err      bool
	}{
		// ip saddr 192.168.10.11 counter packets 5 bytes 1000 drop
		{
			nlRule: B().withAddrCmp(hlp.OffsetSAddrV4, []byte{192, 168, 10, 11}).build(expr.VerdictDrop),
			want:   createWantedRule([]string{"192.168.10.11"}, nil, nil, nil, "drop"),
		},

		// ip saddr adc6:ef93::1 counter packets 5 bytes 1000 jump somewhere
		{
			nlRule: B().
				withAddrCmp(hlp.OffsetSAddrV6, []byte{173, 198, 239, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}).
				build(expr.VerdictJump),
			want: createWantedRule([]string{"adc6:ef93::1"}, nil, nil, nil, "policy"),
		},

		// ip daddr @NetIPv4-sg-dmy1 counter packets 5 bytes 1000 accept
		{
			nlRule:   B().withAddrLookup(hlp.OffsetDAddrV4, "NetIPv4-sg-dmy1").build(expr.VerdictAccept),
			setsConf: setDictFromMap(sgDmySet),
			want:     createWantedRule(nil, []string{"@NetIPv4-sg-dmy1"}, nil, nil, "accept"),
		},

		// tcp dport 20-40 counter packets 5 bytes 1000 accept
		{
			nlRule: B().
				withPortsCmp(
					hlp.OffsetDPort,
					[]expr.Any{
						&expr.Cmp{
							Op:   expr.CmpOpGte,
							Data: []byte{0, 20},
						},
						&expr.Cmp{
							Op:   expr.CmpOpLte,
							Data: []byte{0, 40},
						}}).
				build(expr.VerdictAccept),
			want: createWantedRule(nil, nil, nil, []string{"20", "40"}, "accept"),
		},

		// tcp sport { 1, 2, 3, 1000 } counter packets 5 bytes 1000 drop
		{
			nlRule: B().withPortsLookup(hlp.OffsetSPort, "__set0").build(expr.VerdictDrop),
			// non interval set like nft cli do it
			setsConf: setDictFromMap(map[string]conf.NfSet{
				"__set0": {
					Set: &nft.Set{
						Name:      "__set0",
						Anonymous: true,
					},
					Elements: []nft.SetElement{
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
			}),
			want: createWantedRule(nil, nil, []string{"1", "2", "3", "1000"}, nil, "drop"),
		},

		// tcp sport { 80, 90 } counter packets 5 bytes 1000 accept
		{
			nlRule: B().withPortsLookup(hlp.OffsetSPort, "__set1").build(expr.VerdictAccept),
			// interval set like sgroups do it
			setsConf: setDictFromMap(map[string]conf.NfSet{
				"__set1": {
					Set: &nft.Set{
						Name:      "__set1",
						Anonymous: true,
						Interval:  true,
					},
					Elements: []nft.SetElement{
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
			}),
			want: createWantedRule(nil, nil, []string{"80", "90"}, nil, "accept"),
		},

		// meta nftrace set 1 icmp type { 100 } counter packets 5 bytes 1000 log level debug flags ip options drop
		{
			nlRule: createNlRuleWithNftraceAndIcmp("__set2", expr.VerdictDrop),
			setsConf: setDictFromMap(map[string]conf.NfSet{
				"__set2": {
					Set: &nft.Set{
						Name:      "__set2",
						Anonymous: true,
						Constant:  true,
					},
					Elements: []nft.SetElement{
						{
							Key: []byte{100},
						},
					},
				},
			}),
			want: createWantedRule(nil, nil, nil, nil, "drop"),
		},

		// ip saddr @NetIPv4-sg-dmy1 tcp sport 777 tcp dport 555 counter packets 5 bytes 1000 drop
		{
			nlRule: B().withAddrLookup(hlp.OffsetSAddrV4, "NetIPv4-sg-dmy1").
				withPortsCmp(hlp.OffsetSPort, []expr.Any{
					&expr.Cmp{Op: expr.CmpOpEq, Data: []byte{3, 9}},
				}).
				withPortsCmp(hlp.OffsetDPort, []expr.Any{
					&expr.Cmp{Op: expr.CmpOpEq, Data: []byte{2, 43}},
				}).
				build(expr.VerdictDrop),
			setsConf: setDictFromMap(sgDmySet),
			want:     createWantedRule([]string{"@NetIPv4-sg-dmy1"}, nil, []string{"777"}, []string{"555"}, "drop"),
		},
	}

	for i, c := range cases {
		got, err := From(c.nlRule, c.setsConf)
		if !c.err {
			require.NoErrorf(t, err, "TestNl2rule: testcase %d failed", i)
		} else {
			require.Errorf(t, err, "TestNl2rule: testcase %d should fail", i)
		}
		require.Equalf(t, c.want, got, "TestNl2rule: testcase %d got view differs from wanted", i)
	}
}

type nlRuleBuilder struct {
	exprs         []expr.Any
	havePortsMeta bool
}

func B() *nlRuleBuilder {
	return &nlRuleBuilder{}
}

func (b *nlRuleBuilder) build(verdict expr.VerdictKind) *nft.Rule {
	t := &nft.Table{
		Name:   "main",
		Use:    0,
		Flags:  0,
		Family: nft.TableFamilyINet,
	}
	b.exprs = append(b.exprs,
		createCounter(1000, 5),
		&expr.Verdict{
			Kind: verdict,
		},
	)
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
		Exprs:    b.exprs,
		UserData: nil,
	}
}

func (b *nlRuleBuilder) withAddrCmp(addrOffset uint32, ip net.IP) *nlRuleBuilder {
	metaCmp := expr.Cmp{
		Op:   expr.CmpOpEq,
		Data: []byte{unix.NFPROTO_IPV4},
	}
	payload := expr.Payload{
		OperationType: expr.PayloadLoad,
		Base:          expr.PayloadBaseNetworkHeader,
		Offset:        addrOffset,
	}
	switch addrOffset {
	case hlp.OffsetSAddrV4, hlp.OffsetDAddrV4:
		metaCmp.Data = []byte{unix.NFPROTO_IPV4}
	case hlp.OffsetSAddrV6, hlp.OffsetDAddrV6:
		metaCmp.Data = []byte{unix.NFPROTO_IPV6}
	}
	b.exprs = append(b.exprs,
		&expr.Meta{
			Key: expr.MetaKeyNFPROTO,
		},
		&metaCmp,
		&payload,
		&expr.Cmp{
			Op:   expr.CmpOpEq,
			Data: ip,
		},
	)
	return b
}

func (b *nlRuleBuilder) withAddrLookup(addrOffset uint32, setName string) *nlRuleBuilder {
	metaCmp := expr.Cmp{
		Op: expr.CmpOpEq,
	}
	payload := expr.Payload{
		OperationType: expr.PayloadLoad,
		Base:          expr.PayloadBaseNetworkHeader,
		Offset:        addrOffset,
	}
	switch addrOffset {
	case hlp.OffsetSAddrV4, hlp.OffsetDAddrV4:
		metaCmp.Data = []byte{unix.NFPROTO_IPV4}
	case hlp.OffsetSAddrV6, hlp.OffsetDAddrV6:
		metaCmp.Data = []byte{unix.NFPROTO_IPV6}
	}
	b.exprs = append(b.exprs,
		&expr.Meta{Key: expr.MetaKeyNFPROTO},
		&metaCmp,
		&payload,
		&expr.Lookup{SetName: setName},
	)
	return b
}

func (b *nlRuleBuilder) addPortsMeta() *nlRuleBuilder {
	// adds ports meta once
	if !b.havePortsMeta {
		b.exprs = append(b.exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO},
			&expr.Cmp{
				Op:   expr.CmpOpEq,
				Data: []byte{unix.IPPROTO_TCP},
			},
		)
		b.havePortsMeta = true
	}
	return b
}

func (b *nlRuleBuilder) withPortsCmp(portOffset uint32, portCmps []expr.Any) *nlRuleBuilder {
	b.addPortsMeta()
	b.exprs = append(b.exprs,
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			Base:          expr.PayloadBaseTransportHeader,
			Offset:        portOffset,
			Len:           2,
		},
	)
	b.exprs = append(b.exprs, portCmps...)
	return b
}

func (b *nlRuleBuilder) withPortsLookup(portOffset uint32, setName string) *nlRuleBuilder {
	b.addPortsMeta()
	b.exprs = append(b.exprs,
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			Base:          expr.PayloadBaseTransportHeader,
			Offset:        portOffset,
			Len:           2,
		},
		&expr.Lookup{SetName: setName},
	)
	return b
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

func setDictFromMap(m map[string]conf.NfSet) (ret dkt.HDict[string, conf.NfSet]) {
	for k, v := range m {
		ret.Insert(k, v)
	}
	return ret
}

func createWantedRule(aSrc, aDest, pSrc, pDest []string, action string) *RuleView {
	return &RuleView{
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
