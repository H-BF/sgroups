//go:build linux
// +build linux

package nft

import (
	"bytes"
	"container/list"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	"github.com/H-BF/sgroups/internal/config"
	di "github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/backoff"
	"github.com/ahmetb/go-linq/v3"
	"github.com/c-robinson/iplib"
	nftLib "github.com/google/nftables"
	util "github.com/google/nftables/binaryutil"
	nfte "github.com/google/nftables/expr"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	//chnFORWARD     = "FORWARD"
	chnPOSTROUTING = "POSTROUTING"
	//chnPREROUTING  = "PREROUTING"
	chnINPUT = "INPUT"
	chnFWIN  = "FW-IN"
	chnFWOUT = "FW-OUT"
)

const (
	dirIN  direction = true
	dirOUT direction = false
)

type (
	direction bool

	jobItem struct {
		name string
		jobf
	}

	jobf = func(tx *Tx) error

	accports struct {
		sp [][2]model.PortNumber
		dp [][2]model.PortNumber
	}

	ruleDetails struct {
		logs     bool
		trace    bool
		accports []accports
	}

	batch struct {
		log          logger.TypeOfLogger
		txProvider   TxProvider
		baseRules    BaseRules
		data         cases.LocalData
		dnsResolver  internal.DomainAddressQuerier
		fqdnStrategy internal.FqdnRulesStrategy
		table        *nftLib.Table
		ruleDetails  di.HDict[string, *ruleDetails]
		addrsets     di.HDict[string, *nftLib.Set]
		chains       di.HDict[string, *nftLib.Chain]
		jobs         *list.List
	}
)

func (ap accports) sourceOrDestPort(rb ruleBuilder, isSource bool) ruleBuilder {
	src := tern(isSource, ap.sp, ap.dp)
	if n := len(src); n == 1 {
		rb = tern(isSource, rb.sport, rb.dport)()
		if p := src[0]; p[0] == p[1] {
			rb = rb.eqU16(p[0])
		} else {
			rb = rb.geU16(p[0]).leU16(p[1])
		}
	} else if n > 1 { //add anonimous port set
		set := &nftLib.Set{
			ID:        nextSetID(),
			Name:      "__set%d",
			Interval:  true,
			Anonymous: true,
			Constant:  true,
			KeyType:   nftLib.TypeInetService,
		}
		elements := make([]nftLib.SetElement, 0, 2*n)
		for _, p := range src {
			elements = append(elements,
				nftLib.SetElement{
					Key: util.BigEndian.PutUint16(p[0]),
				},
				nftLib.SetElement{
					Key:         util.BigEndian.PutUint16(p[1] + 1),
					IntervalEnd: true,
				},
			)
		}
		rb = tern(isSource, rb.sport, rb.dport)().inSet(set)
		rb.sets.Put(set.ID, NfSet{Set: set, Elements: elements})
	}
	return rb
}

// S - means 'sports'
func (ap accports) S(rb ruleBuilder) ruleBuilder {
	return ap.sourceOrDestPort(rb, true)
}

// S - means 'dports'
func (ap accports) D(rb ruleBuilder) ruleBuilder {
	return ap.sourceOrDestPort(rb, false)
}

// String -
func (ap accports) String() string {
	b := bytes.NewBuffer(nil)
	ports := sli(ap.sp, ap.dp)
	for i, lb := range sli("s:", "d:") {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(lb)
		if pp := ports[i]; len(pp) == 0 {
			b.WriteByte('*')
		} else {
			for j := range pp {
				if j > 0 {
					b.WriteByte(',')
				}
				x := pp[j]
				fmt.Fprintf(b, "%v", x[0])
				if x[0] != x[1] {
					fmt.Fprintf(b, "-%v", x[1])
				}
			}
		}
	}
	return b.String()
}

func (bt *batch) prepare() {
	bt.addrsets.Clear()
	bt.chains.Clear()
	bt.ruleDetails.Clear()
	bt.jobs = nil
	bt.table = nil

	bt.initTable()
	bt.addSGNetSets()
	bt.addFQDNNetSets()
	bt.initSG2SGRulesDetails()
	bt.initSG2FQDNRulesDetails()
	bt.initCidrSgRulesDetails()
	bt.initSgIeSgRulesDetails()
	bt.initRootChains()
	bt.initBaseRules()
	bt.makeInOutChains(dirIN)
	bt.makeInOutChains(dirOUT)
	bt.fwInOutAddDefaultRules()
	bt.switch2NewConfig()
}

func (bt *batch) addJob(n string, job jobf) {
	if bt.jobs == nil {
		bt.jobs = list.New()
	}
	bt.jobs.PushBack(jobItem{name: n, jobf: job})
}

func (bt *batch) execute(ctx context.Context) error {
	var (
		err error
		it  jobItem
		tx  *Tx
	)
	defer func() {
		if tx != nil {
			_ = tx.Close()
		}
	}()
	bt.prepare()
	bkf := MakeBatchBackoff()
loop:
	for el := bt.jobs.Front(); el != nil; el = bt.jobs.Front() {
		it = bt.jobs.Remove(el).(jobItem)
		bkf.Reset()
		for {
			if tx == nil {
				tx, err = bt.txProvider()
				if err != nil {
					return err
				}
			}
			if err = it.jobf(tx); err != nil {
				break loop
			}
			if err = tx.Flush(); err == nil {
				break
			}
			_ = tx.Close()
			tx = nil
			d := bkf.NextBackOff()
			if d == backoff.Stop {
				break loop
			}
			bt.log.Debugf("'%s' will retry after %s", it.name, d)
			select {
			case <-ctx.Done():
				err = ctx.Err()
				break loop
			case <-time.After(d):
			}
		}
	}
	if err != nil && len(it.name) > 0 {
		err = errors.WithMessage(err, it.name)
	}
	return err
}

func (bt *batch) cleanOnFail(_ context.Context) error {
	if bt.table == nil {
		return nil
	}
	tx, err := bt.txProvider()
	if err != nil {
		return err
	}
	defer tx.Close()
	var tabs []*nftLib.Table
	if tabs, err = tx.ListTables(); err != nil {
		return err
	}
	for _, t := range tabs {
		if t.Name == bt.table.Name && t.Family == bt.table.Family {
			tx.DelTable(t)
			err = tx.Flush()
			break
		}
	}
	return err
}

func (bt *batch) initTable() {
	bt.addJob("init-table", func(tx *Tx) error {
		tlist, e := tx.ListTablesOfFamily(nftLib.TableFamilyINet)
		if e != nil {
			return e
		}
		newTableName := nameUtils{}.genMainTableName()
		for _, o := range tlist {
			if o.Name == newTableName {
				bt.log.Debugf("delete table '%s'", newTableName)
				tx.DelTable(o)
				if e := tx.Flush(); e != nil {
					return e
				}
				break
			}
		}
		bt.log.Debugf("add table '%s'", newTableName)
		bt.table = tx.AddTable(&nftLib.Table{
			Name:   newTableName,
			Family: nftLib.TableFamilyINet,
			Flags:  unix.NFT_TABLE_F_DORMANT,
		})
		return nil
	})
}

func (bt *batch) initRootChains() {
	bt.addJob("init root chains", func(tx *Tx) error {
		/*//
		_ = tx.AddChain(&nftLib.Chain{
			Name:     chnFORWARD,
			Table:    bt.table,
			Type:     nftLib.ChainTypeFilter,
			Policy:   val2ptr(nftLib.ChainPolicyAccept),
			Hooknum:  nftLib.ChainHookForward,
			Priority: nftLib.ChainPriorityFilter,
		})
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnFORWARD)
		*/

		fwInChain := tx.AddChain(&nftLib.Chain{
			Name:  chnFWIN,
			Table: bt.table,
		})
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnFWIN)
		bt.chains.Put(chnFWIN, fwInChain)
		//beginRule().metaNFTRACE(true).
		//	applyRule(fwInChain, tx.Conn)

		fwOutChain := tx.AddChain(&nftLib.Chain{
			Name:  chnFWOUT,
			Table: bt.table,
		})
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnFWOUT)
		bt.chains.Put(chnFWOUT, fwOutChain)
		//beginRule().metaNFTRACE(true).
		//	applyRule(fwOutChain, tx.Conn)

		chnOutput := tx.AddChain(&nftLib.Chain{
			Name:     chnPOSTROUTING,
			Table:    bt.table,
			Type:     nftLib.ChainTypeFilter,
			Policy:   val2ptr(nftLib.ChainPolicyAccept),
			Hooknum:  nftLib.ChainHookPostrouting,
			Priority: nftLib.ChainPriorityConntrackHelper,
			//Hooknum:  nftLib.ChainHookOutput,
			//Priority: nftLib.ChainPriorityFilter,
		})
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnPOSTROUTING)
		bt.chains.Put(chnPOSTROUTING, chnOutput)
		beginRule().
			ctState(nfte.CtStateBitESTABLISHED|nfte.CtStateBitRELATED).
			accept().applyRule(chnOutput, tx.Conn)
		beginRule().oifname().neqS("lo").counter().
			go2(chnFWOUT).applyRule(chnOutput, tx.Conn)

		chnInput := tx.AddChain(&nftLib.Chain{
			//Name:   chnPREROUTING,
			Name:   chnINPUT,
			Table:  bt.table,
			Type:   nftLib.ChainTypeFilter,
			Policy: val2ptr(nftLib.ChainPolicyAccept),
			//Hooknum:  nftLib.ChainHookPrerouting,
			//Priority: nftLib.ChainPriorityRaw,
			Hooknum:  nftLib.ChainHookInput,
			Priority: nftLib.ChainPriorityFilter,
		})
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnINPUT)
		bt.chains.Put(chnINPUT, chnInput)
		beginRule().
			ctState(nfte.CtStateBitESTABLISHED|nfte.CtStateBitRELATED).
			accept().applyRule(chnInput, tx.Conn)
		beginRule().iifname().neqS("lo").counter().
			go2(chnFWIN).applyRule(chnInput, tx.Conn)
		return nil
	})
}

func (bt *batch) initBaseRules() {
	const api = "init-base-rules"

	var nws []model.Network
	linq.From(bt.baseRules.Nets).
		Select(func(i any) any {
			return model.Network{Net: *i.(config.NetCIDR).IPNet}
		}).ToSlice(&nws)

	for i, nw := range sli(cases.SeparateNetworks(nws)) {
		isIP4 := i == 0
		nw := nw
		elems := setsUtils{}.nets2SetElements(nw, tern(isIP4, iplib.IP4Version, iplib.IP6Version))
		if len(elems) > 0 {
			bt.addJob(api, func(tx *Tx) error {
				netSet := &nftLib.Set{
					ID:        nextSetID(),
					Name:      "__set%d",
					Constant:  true,
					Table:     bt.table,
					KeyType:   tern(isIP4, nftLib.TypeIPAddr, nftLib.TypeIP6Addr),
					Interval:  true,
					Anonymous: true,
				}
				if err := tx.AddSet(netSet, elems); err != nil {
					return err
				}
				bt.log.Debugf("add network(s) %s into base rules", slice2stringer(nw...))
				rule := beginRule()
				tern(isIP4, rule.daddr4, rule.daddr6)().
					inSet(netSet).accept().
					applyRule(bt.chains.At(chnFWOUT), tx.Conn)
				return nil
			})
		}
	}
}

func (bt *batch) addSGNetSets() {
	bt.data.Networks.Iterate(func(sgName string, nws []model.Network) bool {
		nwsV4, nwsV6 := cases.SeparateNetworks(nws)
		for i, nets := range sli(nwsV4, nwsV6) {
			isV6 := i > 0
			ipV := tern(isV6, iplib.IP6Version, iplib.IP4Version)
			if elements := (setsUtils{}).nets2SetElements(nets, ipV); len(elements) > 0 {
				bt.addJob("add-sg-net-set", func(tx *Tx) error {
					nameOfSet := nameUtils{}.nameOfNetSet(ipV, sgName)
					netSet := &nftLib.Set{
						ID:       nextSetID(),
						Constant: true,
						Table:    bt.table,
						KeyType:  tern(isV6, nftLib.TypeIP6Addr, nftLib.TypeIPAddr),
						Interval: true,
						Name:     nameOfSet,
					}
					if err := tx.AddSet(netSet, elements); err != nil {
						return err
					}
					bt.addrsets.Put(nameOfSet, netSet)
					bt.log.Debugf("add NET set '%s'/'%s' with items:[%s]",
						bt.table.Name, nameOfSet, slice2stringer(nets...))
					return nil
				})
			}
		}
		return true
	})
}

func (bt *batch) addFQDNNetSets() {
	if bt.fqdnStrategy.Eq(internal.FqdnRulesStartegyNDPI) {
		return
	}
	f := func(IPv int, domain model.FQDN, a internal.DomainAddresses) {
		bt.addJob("add-fqdn-net-sets", func(tx *Tx) error {
			nameOfSet := nameUtils{}.nameOfFqdnNetSet(IPv, domain)
			nets := make([]net.IPNet, len(a.IPs))
			isV6 := IPv == iplib.IP6Version
			bits := tern(isV6, net.IPv6len, net.IPv4len) * 8
			mask := net.CIDRMask(bits, bits)
			for i, ip := range a.IPs {
				nets[i] = net.IPNet{IP: ip, Mask: mask}
			}
			elements := (setsUtils{}).nets2SetElements(nets, IPv)
			netSet := &nftLib.Set{
				ID:       nextSetID(),
				Table:    bt.table,
				KeyType:  tern(isV6, nftLib.TypeIP6Addr, nftLib.TypeIPAddr),
				Interval: true,
				Name:     nameOfSet,
			}
			if err := tx.AddSet(netSet, elements); err != nil {
				return err
			}
			bt.addrsets.Put(nameOfSet, netSet)
			bt.log.Debugf("add network-set '%s'/'%s' items:[%s]",
				bt.table.Name, nameOfSet, slice2stringer(nets...))
			if len(nets) == 0 {
				bt.log.Warnf("add IP-set '%s'/'%s' no any IP%v address is resolved for domain '%s'",
					bt.table.Name, nameOfSet, IPv, domain)
			} else {
				bt.log.Debugf("add IP-set '%s'/'%s' with items:[%s]",
					bt.table.Name, nameOfSet, slice2stringer(nets...))
			}
			return nil
		})
	}

	bt.data.ResolvedFQDN.A.Iterate(func(domain model.FQDN, a internal.DomainAddresses) bool {
		f(iplib.IP4Version, domain, a)
		return true
	})
	bt.data.ResolvedFQDN.AAAA.Iterate(func(domain model.FQDN, a internal.DomainAddresses) bool {
		f(iplib.IP6Version, domain, a)
		return true
	})
}

func (bt *batch) initSG2SGRulesDetails() {
	for _, r := range bt.data.SG2SGRules.AllRules() {
		item := ruleDetails{
			accports: setsUtils{}.makeAccPorts(r.Ports),
			logs:     r.Logs,
		}
		if len(item.accports) == 0 {
			item.accports = append(item.accports, accports{})
		}
		setName := nameUtils{}.nameOfSG2SGRuleDetails(
			r.ID.Transport,
			r.ID.SgFrom,
			r.ID.SgTo)
		bt.ruleDetails.Put(setName, &item)
	}
}

func (bt *batch) initSG2FQDNRulesDetails() {
	for _, r := range bt.data.SG2FQDNRules.Rules {
		item := ruleDetails{
			accports: setsUtils{}.makeAccPorts(r.Ports),
			logs:     r.Logs,
		}
		if len(item.accports) == 0 {
			item.accports = append(item.accports, accports{})
		}
		setName := nameUtils{}.nameOfSG2FQDNRuleDetails(
			r.ID.Transport,
			r.ID.SgFrom,
			r.ID.FqdnTo,
		)
		bt.ruleDetails.Put(setName, &item)
	}
}

func (bt *batch) initCidrSgRulesDetails() {
	bt.data.CidrSgRules.Rules.Iterate(func(_ model.CidrSgRuleIdenity, r *model.CidrSgRule) bool {
		item := ruleDetails{
			accports: setsUtils{}.makeAccPorts(r.Ports),
			logs:     r.Logs,
			trace:    r.Trace,
		}
		if len(item.accports) == 0 {
			item.accports = append(item.accports, accports{})
		}
		bt.ruleDetails.Put(
			nameUtils{}.nameCidrSgRuleDetails(r),
			&item,
		)
		return true
	})
}

func (bt *batch) initSgIeSgRulesDetails() {
	bt.data.SgIeSgRules.Rules.Iterate(func(_ model.SgSgRuleIdentity, r *model.SgSgRule) bool {
		item := ruleDetails{
			accports: setsUtils{}.makeAccPorts(r.Ports),
			logs:     r.Logs,
			trace:    r.Trace,
		}
		if len(item.accports) == 0 {
			item.accports = append(item.accports, accports{})
		}
		bt.ruleDetails.Put(
			nameUtils{}.nameSgIeSgRuleDetails(r),
			&item,
		)
		return true
	})
}

func (bt *batch) populateOutSgFqdnRules(sg *cases.SG) {
	const (
		useDNS = 1 << iota
		useNDPI
	)
	var strategy int
	if bt.fqdnStrategy.Eq(internal.FqdnRulesStartegyNDPI) {
		strategy = useNDPI
	} else if bt.fqdnStrategy.Eq(internal.FqdnRulesStartegyDNS) {
		strategy = useDNS
	} else if bt.fqdnStrategy.Eq(internal.FqdnRulesStartegyCombine) {
		strategy = useNDPI | useDNS
	}

	targetChName := nameUtils{}.nameOfInOutChain(dirOUT, sg.Name)
	rules := bt.data.SG2FQDNRules.RulesForSG(sg.Name)
	for _, ipV := range sli(model.IPv4, model.IPv6) {
		ipV := ipV
		for _, rule := range rules {
			detailsName := nameUtils{}.nameOfSG2FQDNRuleDetails(
				rule.ID.Transport, rule.ID.SgFrom, rule.ID.FqdnTo,
			)
			daddrSetName := nameUtils{}.nameOfFqdnNetSet(ipV, rule.ID.FqdnTo)
			rd := bt.ruleDetails.At(detailsName)
			rule := rule
			for i := range rd.accports {
				ports := rd.accports[i]
				bt.addJob("populate-fqdn-rule", func(tx *Tx) error {
					chnApplyTo := bt.chains.At(targetChName)
					if chnApplyTo == nil {
						return nil
					}
					daddr := bt.addrsets.At(daddrSetName)
					if daddr == nil && strategy&useDNS != 0 {
						return nil
					}
					if daddr != nil {
						bt.log.Debugf("add fqdn rule '%s' with '%s' strategy into '%s'/'%s' for addr-set '%s'",
							rule.ID.FqdnTo, string(bt.fqdnStrategy), bt.table.Name, targetChName, daddrSetName)
					} else {
						bt.log.Debugf("add fqdn rule '%s' with '%s' strategy into '%s'/'%s'",
							rule.ID.FqdnTo, string(bt.fqdnStrategy), bt.table.Name, targetChName)
					}
					r := beginRule()
					if strategy&useDNS != 0 {
						r = r.daddr(ipV).inSet(daddr)
					}
					r = ports.D(
						ports.S(
							r.protoIP(rule.ID.Transport),
						),
					)
					if strategy&useNDPI != 0 {
						var protocols []string
						rule.NdpiProtocols.Iterate(func(k di.StringCiKey) bool {
							protocols = append(protocols, string(k))
							return true
						})
						r = r.ndpi(rule.ID.FqdnTo, protocols...)
					}
					r = r.counter()
					if rd.logs {
						r = r.dlogs(nfte.LogFlagsIPOpt)
					}
					r.accept().applyRule(chnApplyTo, tx.Conn)
					return nil
				})
			}
		}
		if strategy&useDNS == 0 {
			break
		}
	}
}

func (bt *batch) populateDefaultIcmpRules(dir direction, sg *cases.SG) {
	targetChName := nameUtils{}.nameOfInOutChain(dir, sg.Name)
	rules := bt.data.SgIcmpRules.Rules4Sg(sg.Name)
	for i := range rules {
		rule := rules[i]
		bt.addJob("populate-def-icmp-rule", func(tx *Tx) error {
			chnApplyTo := bt.chains.At(targetChName)
			if chnApplyTo != nil {
				tern(rule.Icmp.IPv == model.IPv6, "6", "")
				bt.log.Debugf("add default-icmp%v-rule into '%s'/'%s'",
					tern(rule.Icmp.IPv == model.IPv6, "6", ""),
					bt.table.Name, targetChName)
				rb := beginRule().metaNFTRACE(rule.Trace).
					protoICMP(rule.Icmp).
					counter()
				if rule.Logs {
					rb = rb.dlogs(nfte.LogFlagsIPOpt)
				}
				rb.accept().applyRule(chnApplyTo, tx.Conn)
			}
			return nil
		})
	}
}

func (bt *batch) populateInOutSgIcmpRules(dir direction, sg *cases.SG) {
	targetChName := nameUtils{}.nameOfInOutChain(dir, sg.Name)
	isIN := dir == dirIN
	rules := tern(isIN,
		bt.data.SgSgIcmpRules.In, bt.data.SgSgIcmpRules.Out,
	)(sg.Name)
	api := fmt.Sprintf("populate-%s-sg-icmp-rule", tern(isIN, "in", "out"))
	for i := range rules {
		rule := rules[i]
		bt.addJob(api, func(tx *Tx) error {
			addrSetName := nameUtils{}.nameOfNetSet(
				int(rule.Icmp.IPv),
				tern(isIN, rule.SgFrom, rule.SgTo),
			)
			chnApplyTo := bt.chains.At(targetChName)
			addrSet := bt.addrsets.At(addrSetName)
			if addrSet != nil && chnApplyTo != nil {
				bt.log.Debugf("add %s-sg-icmp%v-rule for addr-set '%s' into '%s'/'%s'",
					tern(isIN, "in", "out"),
					tern(rule.Icmp.IPv == model.IPv6, "6", ""),
					addrSetName, targetChName, bt.table.Name)
				rb := beginRule().metaNFTRACE(rule.Trace)
				rb = tern(isIN, rb.saddr, rb.daddr)(int(rule.Icmp.IPv)).
					inSet(addrSet).
					protoICMP(rule.Icmp).
					counter()
				if rule.Logs {
					rb = rb.dlogs(nfte.LogFlagsIPOpt)
				}
				rb.accept().applyRule(chnApplyTo, tx.Conn)
			}
			return nil
		})
	}
}

func (bt *batch) populateInOutSgRules(dir direction, sg *cases.SG) {
	targetSGchName := nameUtils{}.nameOfInOutChain(dir, sg.Name)
	isIN := dir == dirIN
	rules := tern(isIN, bt.data.SG2SGRules.In, bt.data.SG2SGRules.Out)(sg.Name)
	api := fmt.Sprintf("populate-%s-sg-rule", tern(isIN, "in", "out"))
	for _, ipV := range sli(model.IPv4, model.IPv6) {
		ipV := ipV
		for _, rule := range rules {
			rule := rule
			addrSetName := nameUtils{}.nameOfNetSet(ipV,
				tern(isIN, rule.ID.SgFrom, rule.ID.SgTo))

			detailsName := nameUtils{}.nameOfSG2SGRuleDetails(rule.ID.Transport,
				tern(isIN, rule.ID.SgFrom, sg.Name),
				tern(isIN, sg.Name, rule.ID.SgTo))

			details := bt.ruleDetails.At(detailsName)
			if details == nil {
				continue
			}
			for i := range details.accports { //nolint:dupl
				ports := details.accports[i]
				bt.addJob(api, func(tx *Tx) error {
					chnApplyTo := bt.chains.At(targetSGchName)
					addrSet := bt.addrsets.At(addrSetName)
					if chnApplyTo != nil && addrSet != nil {
						bt.log.Debugf("add %s-sg-rule for addr-set '%s' into '%s'/'%s'",
							tern(isIN, "in", "out"),
							addrSetName, bt.table.Name, targetSGchName)
						r := beginRule()
						if isIN {
							r = ports.S(
								ports.D(
									r.saddr(ipV).inSet(addrSet).
										protoIP(rule.ID.Transport),
								),
							)
						} else {
							r = ports.D(
								ports.S(
									r.daddr(ipV).inSet(addrSet).
										protoIP(rule.ID.Transport),
								),
							)
						}
						r = r.counter()
						if details.logs {
							r = r.dlogs(nfte.LogFlagsIPOpt)
						}
						r.accept().applyRule(chnApplyTo, tx.Conn)
					}
					return nil
				})
			}
		}
	}
}

func (bt *batch) populateInOutSgIeSgRules(dir direction, sg *cases.SG) {
	isIN := dir == dirIN
	rules := bt.data.SgIeSgRules.GetRulesForTrafficAndSG(
		tern(isIN, model.INGRESS, model.EGRESS), sg.Name,
	)
	targetSGchName := nameUtils{}.nameOfInOutChain(dir, sg.Name)
	api := fmt.Sprintf("populate-sg-%sgress-sg-rule(s)", tern(isIN, "in", "e"))
	for _, ipV := range sli(model.IPv4, model.IPv6) {
		ipV := ipV
		for _, rule := range rules {
			rule := rule
			addrSetName := nameUtils{}.nameOfNetSet(
				ipV, tern(isIN, rule.ID.SgLocal, rule.ID.Sg),
			)
			detailsName := nameUtils{}.nameSgIeSgRuleDetails(rule)
			details := bt.ruleDetails.At(detailsName)
			if details == nil {
				continue
			}
			for i := range details.accports {
				ports := details.accports[i]
				bt.addJob(api, func(tx *Tx) error {
					chnApplyTo := bt.chains.At(targetSGchName)
					addrSet := bt.addrsets.At(addrSetName)
					if chnApplyTo == nil || addrSet == nil {
						return nil
					}
					bt.log.Debugf("add '%s' rule for accports(%s) into '%s'/'%s'",
						rule.ID, ports, bt.table.Name, targetSGchName)

					rb := beginRule().metaNFTRACE(details.trace)
					sd := tern(isIN, sli(ports.S, ports.D), sli(ports.D, ports.S))
					rb = sd[0](sd[1](
						tern(isIN, rb.saddr, rb.daddr)(ipV).inSet(addrSet).
							protoIP(rule.ID.Transport),
					)).counter()
					if details.logs {
						rb = rb.dlogs(nfte.LogFlagsIPOpt)
					}
					rb.accept().applyRule(chnApplyTo, tx.Conn)
					return nil
				})
			}
		}
	}
}

func (bt *batch) populateInOutCidrSgRules(dir direction, sg *cases.SG) {
	isIN := dir == dirIN
	rules := bt.data.CidrSgRules.GetRulesForTrafficAndSG(
		tern(isIN, model.INGRESS, model.EGRESS),
		sg.Name,
	)
	api := fmt.Sprintf("populate-cidr-sg-%sgress-rule", tern(isIN, "in", "e"))
	targetSGchName := nameUtils{}.nameOfInOutChain(dir, sg.Name)
	for _, rule := range rules {
		rule := rule
		detailsName := nameUtils{}.nameCidrSgRuleDetails(rule)
		details := bt.ruleDetails.At(detailsName)
		if details == nil {
			continue
		}
		for i := range details.accports {
			ports := details.accports[i]
			bt.addJob(api, func(tx *Tx) error {
				bt.log.Debugf("add '%s' rule into '%s'/'%s'",
					rule.ID, bt.table.Name, targetSGchName)
				chnApplyTo := bt.chains.At(targetSGchName)
				if chnApplyTo == nil {
					return nil
				}
				rb := beginRule().
					metaNFTRACE(details.trace).
					srcOrDstSingleIpNet(rule.ID.CIDR, isIN).
					protoIP(rule.ID.Transport)
				rb = ports.D(ports.S(rb)).counter()
				if details.logs {
					rb = rb.dlogs(nfte.LogFlagsIPOpt)
				}
				rb.accept().applyRule(chnApplyTo, tx.Conn)
				return nil
			})
		}
	}
}

func (bt *batch) makeInOutChains(dir direction) {
	bt.data.LocalSGs.Iterate(func(_ string, sg *cases.SG) bool {
		bt.chainInOutProlog(dir, sg)
		bt.populateDefaultIcmpRules(dir, sg)
		bt.populateInOutSgIcmpRules(dir, sg)
		bt.populateInOutSgRules(dir, sg)
		bt.populateInOutSgIeSgRules(dir, sg)
		if dir == dirOUT {
			bt.populateOutSgFqdnRules(sg)
		}
		bt.populateInOutCidrSgRules(dir, sg)
		bt.chainInOutEpilog(dir, sg)
		return true
	})
}

func (bt *batch) chainInOutProlog(dir direction, sg *cases.SG) {
	sgChName := nameUtils{}.nameOfInOutChain(dir, sg.Name)
	isIN := dir == dirIN
	api := fmt.Sprintf("%s-chain-prolog", tern(isIN, "in", "out"))
	for _, ipV := range sli(model.IPv4, model.IPv6) {
		destChainName := tern(dir == dirIN, chnFWIN, chnFWOUT)
		ipV := ipV
		bt.addJob(api, func(tx *Tx) error {
			addrSetName := nameUtils{}.nameOfNetSet(ipV, sg.Name)
			if addrSet := bt.addrsets.At(addrSetName); addrSet != nil {
				if bt.chains.At(sgChName) == nil {
					chn := tx.AddChain(&nftLib.Chain{
						Name:  sgChName,
						Table: bt.table,
					})
					bt.chains.Put(sgChName, chn)
					bt.log.Debugf("chain '%s'/'%s' is in progress",
						bt.table.Name, sgChName)
				}
				bt.log.Debugf("add goto-rule '%s'/('%s' -> '%s')",
					bt.table.Name, destChainName, sgChName)
				destChain := bt.chains.At(destChainName)
				rb := beginRule()
				tern(isIN, rb.daddr, rb.saddr)(ipV).
					inSet(addrSet).
					counter().
					go2(sgChName).
					applyRule(destChain, tx.Conn)
			}
			return nil
		})
	}
}

func (bt *batch) chainInOutEpilog(dir direction, sg *cases.SG) {
	sgChainName := nameUtils{}.nameOfInOutChain(dir, sg.Name)
	bt.addJob(tern(dir == dirIN, "in", "out")+"-chain-epilog",
		func(tx *Tx) error {
			chnApplyTo := bt.chains.At(sgChainName)
			if chnApplyTo == nil {
				return nil
			}
			r := beginRule().metaNFTRACE(sg.Trace).counter()
			if sg.Logs {
				r = r.dlogs(nfte.LogFlagsIPOpt)
			}
			switch da := sg.DefaultAction; da {
			case model.ACCEPT:
				r = r.accept()
			case model.DROP, model.DEFAULT:
				r = r.drop()
			default:
				panic(
					errors.Errorf("for chain '%s'/'%s' provided unsupported default verdict '%v'",
						bt.table.Name, sgChainName, da),
				)
			}
			r.applyRule(chnApplyTo, tx.Conn)
			bt.log.Debugf("chain '%s'/'%s' finished",
				bt.table.Name, sgChainName)
			return nil
		})
}

func (bt *batch) fwInOutAddDefaultRules() {
	for _, chName := range sli(chnFWIN, chnFWOUT) {
		chName := chName
		bt.addJob("add-default-rules", func(tx *Tx) error {
			bt.log.Debugf("add defult rules into chain '%s'/'%s'", chName, bt.table.Name)
			beginRule().drop().applyRule(bt.chains.At(chName), tx.Conn)
			return nil
		})
	}
}

func (bt *batch) switch2NewConfig() {
	bt.addJob("enable-new-config", func(tx *Tx) error {
		if bt.table.Flags&uint32(unix.NFT_TABLE_F_DORMANT) != 0 {
			bt.table.Flags &= ^uint32(unix.NFT_TABLE_F_DORMANT)
			bt.log.Debugf("activate table '%s'", bt.table.Name)
			_ = tx.AddTable(bt.table)
		}
		return nil
	})
	bt.addJob("del-nonactual-configs", func(tx *Tx) error {
		tables, err := tx.ListTables()
		if err != nil {
			return err
		}
		var names nameUtils
		for _, t := range tables {
			if names.isLikeMainTableName(t.Name) && t.Name != bt.table.Name {
				bt.log.Debugf("delete table '%s'", t.Name)
				tx.DelTable(t)
			}
		}
		return nil
	})
}
