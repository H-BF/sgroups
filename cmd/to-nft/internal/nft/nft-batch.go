//go:build linux
// +build linux

package nft

import (
	"container/list"
	"context"
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
)

const (
	//chnFORWARD     = "FORWARD"
	chnPOSTROUTING = "POSTROUTING"
	//chnPREROUTING  = "PREROUTING"
	chnINPUT = "INPUT"
	chnFWIN  = "FW-IN"
	chnFWOUT = "FW-OUT"
)

type (
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
		accports []accports
	}

	batch struct {
		log        logger.TypeOfLogger
		txProvider TxProvider
		tableName  string

		networks       cases.SGsNetworks
		localRules     cases.SG2SGRules
		baseRules      BaseRules
		sg2fqdnRules   cases.SG2FQDNRules
		sg2sgIcmpRules cases.SgSgIcmpRules

		table       *nftLib.Table
		ruleDetails di.HDict[string, *ruleDetails]
		addrsets    di.HDict[string, *nftLib.Set]
		chains      di.HDict[string, *nftLib.Chain]
		jobs        *list.List
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
	bt.initRootChains()
	bt.initBaseRules()
	bt.makeInChains()
	bt.makeOutChains()
	bt.addFinalRules()
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

func delTables(tx *Tx, tbls ...*nftLib.Table) error {
	const api = "del-table(s)"

	var toDel di.HDict[NfTableKey, bool]
	for _, tbl := range tbls {
		toDel.Put(NfTableKey{tbl.Family, tbl.Name}, true)
	}
	if toDel.Len() == 0 {
		return nil
	}
	tableList, err := tx.ListTables()
	if err != nil {
		return errors.WithMessagef(err, "%s: get list of tables", api)
	}
	for _, tbl := range tableList {
		if toDel.At(NfTableKey{tbl.Family, tbl.Name}) {
			tx.DelTable(tbl)
		}
	}
	err = tx.Flush()
	return errors.WithMessage(err, api)
}

func addTables(tx *Tx, tbs ...*nftLib.Table) error {
	const api = "add-table(s)"
	if len(tbs) == 0 {
		return nil
	}
	for _, tbl := range tbs {
		tx.AddTable(tbl)
	}
	return errors.WithMessage(tx.Flush(), api)
}

func (bt *batch) initTable() {
	bt.table = &nftLib.Table{
		Name:   bt.tableName,
		Family: nftLib.TableFamilyINet,
	}
	bt.addJob("del-table", func(tx *Tx) error {
		bt.log.Debugf("check and delete table '%s'", bt.table.Name)
		return delTables(tx, bt.table)
	})
	bt.addJob("add-table", func(tx *Tx) error {
		bt.log.Debugf("add table '%s'", bt.table.Name)
		return addTables(tx, bt.table)
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
	const api = "add-SG-net-sets"

	bt.networks.Iterate(func(sgName string, nws []model.Network) bool {
		ok := bt.localRules.SGs.At(sgName) != nil ||
			bt.sg2fqdnRules.SGs.At(sgName) != nil
		if !ok {
			return true
		}
		nwsV4, nwsV6 := cases.SeparateNetworks(nws)
		for i, nets := range sli(nwsV4, nwsV6) {
			isV6 := i > 0
			ipV := tern(isV6, iplib.IP6Version, iplib.IP4Version)
			if elements := (setsUtils{}).nets2SetElements(nets, ipV); len(elements) > 0 {
				bt.addJob(api, func(tx *Tx) error {
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
					bt.log.Debugf("add IP set '%s'/'%s' with items:[%s]",
						bt.table.Name, nameOfSet, slice2stringer(nets...))
					return nil
				})
			}
		}
		return true
	})
}

func (bt *batch) addFQDNNetSets() {
	const api = "add-FQDN-net-sets"

	f := func(IPv int, domain model.FQDN, a internal.DomainAddresses) {
		bt.addJob(api, func(tx *Tx) error {
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
			bt.log.Debugf("add network set '%s'/'%s' items:[%s]",
				bt.table.Name, nameOfSet, slice2stringer(nets...))
			if len(nets) == 0 {
				bt.log.Warnf("add IP set '%s'/'%s' no any IP%v address is resolved for domain '%s'",
					bt.table.Name, nameOfSet, IPv, domain)
			} else {
				bt.log.Debugf("add IP set '%s'/'%s' with items:[%s]",
					bt.table.Name, nameOfSet, slice2stringer(nets...))
			}
			return nil
		})
	}

	bt.sg2fqdnRules.A.Iterate(func(domain model.FQDN, a internal.DomainAddresses) bool {
		f(iplib.IP4Version, domain, a)
		return true
	})
	bt.sg2fqdnRules.AAAA.Iterate(func(domain model.FQDN, a internal.DomainAddresses) bool {
		f(iplib.IP6Version, domain, a)
		return true
	})
}

func (bt *batch) initSG2SGRulesDetails() {
	for _, r := range bt.localRules.AllRules() {
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
	for _, r := range bt.sg2fqdnRules.Rules {
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

func (bt *batch) makeOutChain(tmpl cases.RulesOutTemplate) {
	const api = "make-out-chains"

	outSGchName := chnFWOUT + "-" + tmpl.SgOut.Name
	bt.addJob(api, func(tx *Tx) error {
		chn := tx.AddChain(&nftLib.Chain{Name: outSGchName, Table: bt.table})
		bt.chains.Put(outSGchName, chn)
		bt.log.Debugf("chain '%s'/'%s' is in progress", bt.table.Name, outSGchName)
		return nil
	})
	for _, ipV := range sli(iplib.IP4Version, iplib.IP6Version) {
		ipV := ipV
		bt.addJob(api, func(tx *Tx) error {
			saddrSetName := nameUtils{}.nameOfNetSet(ipV, tmpl.SgOut.Name)
			if saddrSet := bt.addrsets.At(saddrSetName); saddrSet != nil {
				output := bt.chains.At(chnFWOUT)
				beginRule().
					saddr(ipV).inSet(saddrSet).counter().
					go2(outSGchName).applyRule(output, tx.Conn)
			}
			return nil
		})
	}
	bt.populateSG2SGOutRules(tmpl, outSGchName)
	bt.populateSG2FQDNOutRules(tmpl, outSGchName)
	bt.addJob(api, func(tx *Tx) error {
		r := beginRule().metaNFTRACE(tmpl.SgOut.Trace).counter()
		if tmpl.SgOut.Logs {
			r = r.dlogs(nfte.LogFlagsIPOpt)
		}
		switch da := tmpl.SgOut.DefaultAction; da {
		case model.ACCEPT:
			r = r.accept()
		case model.DROP, model.DEFAULT:
			r = r.drop()
		default:
			panic(
				errors.Errorf("for chain '%s'/'%s' provided unsupported default verdict '%v'",
					bt.table.Name, outSGchName, da),
			)
		}
		chnApplyTo := bt.chains.At(outSGchName)
		r.applyRule(chnApplyTo, tx.Conn)
		bt.log.Debugf("chain '%s'/'%s' finished", bt.table.Name, outSGchName)
		return nil
	})
}

func (bt *batch) makeOutChains() {
	outTmpls := bt.localRules.TemplatesOutRules()
	bt.sg2fqdnRules.SGs.Iterate(func(sgName string, v *cases.SG) bool {
		if _, found := outTmpls.Get(sgName); !found {
			_ = outTmpls.Insert(sgName,
				cases.RulesOutTemplate{SgOut: v.SecurityGroup})
		}
		return true
	})
	outTmpls.Iterate(func(_ string, tmpl cases.RulesOutTemplate) bool {
		bt.makeOutChain(tmpl)
		return true
	})
}

func (bt *batch) populateSG2FQDNOutRules(tm cases.RulesOutTemplate, outChainName string) {
	rules := bt.sg2fqdnRules.RulesForSG(tm.SgOut.Name)
	IPvv := sli(iplib.IP4Version, iplib.IP6Version)
	var names nameUtils
	for i := range rules {
		i, rule := i, rules[i] //nolint:govet
		detailsName := names.nameOfSG2FQDNRuleDetails(
			rule.ID.Transport, rule.ID.SgFrom, rule.ID.FqdnTo,
		)
		rd := bt.ruleDetails.At(detailsName)
		for j := range IPvv {
			j, IPv := j, IPvv[j] //nolint:govet
			daddrSetName := names.nameOfFqdnNetSet(IPv, rule.ID.FqdnTo)
			for n := range rd.accports {
				ports := rd.accports[n]
				bt.addJob("poplulate-SG-FQDN-rules", func(tx *Tx) error {
					if i == 0 && j == 0 {
						bt.log.Debugf("chain '%s'/'%s' SG-FQDN rules are in progress",
							bt.table.Name, outChainName)
					} else if i == len(tm.In)-1 && j == len(IPvv)-1 {
						defer bt.log.Debugf("chain '%s'/'%s' SG-FQDN rules are finished",
							bt.table.Name, outChainName)
					}
					daddr := bt.addrsets.At(daddrSetName)
					if daddr == nil {
						return nil
					}
					r := ports.D(
						ports.S(
							beginRule().daddr(IPv).inSet(daddr).ipProto(rule.ID.Transport),
						),
					).counter()
					if rd.logs {
						r = r.dlogs(nfte.LogFlagsIPOpt)
					}
					chnApplyTo := bt.chains.At(outChainName)
					r.accept().applyRule(chnApplyTo, tx.Conn)
					return nil
				})
			}
		}
	}
}

func (bt *batch) populateSG2SGOutRules(tm cases.RulesOutTemplate, outChainName string) {
	IPvv := sli(iplib.IP4Version, iplib.IP6Version)
	var names nameUtils
	for i := range tm.In {
		i := i
		in := tm.In[i]
		detailsName := names.nameOfSG2SGRuleDetails(in.Proto, tm.SgOut.Name, in.Sg)
		rd := bt.ruleDetails.At(detailsName)
		for j := range IPvv {
			j := j
			IPv := IPvv[j]
			daddrSetName := names.nameOfNetSet(IPv, in.Sg)
			for n := range rd.accports {
				ports := rd.accports[n]
				bt.addJob("poplulate-SG-SG-rules", func(tx *Tx) error {
					if i == 0 && j == 0 {
						bt.log.Debugf("chain '%s'/'%s' SG-SG rules are in progress",
							bt.table.Name, outChainName)
					} else if i == len(tm.In)-1 && j == len(IPvv)-1 {
						defer bt.log.Debugf("chain '%s'/'%s' SG-SG rules are finished",
							bt.table.Name, outChainName)
					}
					daddr := bt.addrsets.At(daddrSetName)
					if daddr == nil {
						return nil
					}
					r := ports.D(
						ports.S(
							beginRule().daddr(IPv).inSet(daddr).ipProto(in.Proto),
						),
					).counter()
					if rd.logs {
						r = r.dlogs(nfte.LogFlagsIPOpt)
					}
					chnApplyTo := bt.chains.At(outChainName)
					r.accept().applyRule(chnApplyTo, tx.Conn)
					return nil
				})
			}
		}
	}
}

func (bt *batch) aggAllInSGs() cases.SGs {
	var ret cases.SGs
	bt.localRules.Rules.Iterate(func(k model.SGRuleIdentity, _ *model.SGRule) bool {
		if sg, _ := bt.localRules.SGs.Get(k.SgTo); sg != nil {
			_ = ret.Insert(sg.Name, sg)
		}
		return true
	})
	bt.sg2sgIcmpRules.Rules.Iterate(func(k model.SgSgIcmpRuleID, _ *model.SgSgIcmpRule) bool {
		if sg, _ := bt.sg2sgIcmpRules.SGs.Get(k.SgTo); sg != nil {
			_ = ret.Insert(sg.Name, sg)
		}
		return true
	})
	return ret
}

func (bt *batch) aggAllOutSGs() cases.SGs {
	var ret cases.SGs
	bt.localRules.Rules.Iterate(func(k model.SGRuleIdentity, _ *model.SGRule) bool {
		if sg, _ := bt.localRules.SGs.Get(k.SgFrom); sg != nil {
			_ = ret.Insert(sg.Name, sg)
		}
		return true
	})
	bt.sg2fqdnRules.SGs.Iterate(func(_ string, sg *cases.SG) bool {
		_ = ret.Insert(sg.Name, sg)
		return true
	})
	bt.sg2sgIcmpRules.Rules.Iterate(func(k model.SgSgIcmpRuleID, _ *model.SgSgIcmpRule) bool {
		if sg, _ := bt.sg2sgIcmpRules.SGs.Get(k.SgFrom); sg != nil {
			_ = ret.Insert(sg.Name, sg)
		}
		return true
	})
	return ret
}

func (bt *batch) makeInChains() {
	const api = "make-in-chains"

	allSgs := bt.aggAllInSGs()
	_ = allSgs

	inTmpls := bt.localRules.TemplatesInRules()
	for _, it := range inTmpls.Items() {
		tmpl := it.V
		inSGchName := chnFWIN + "-" + tmpl.SgIn.Name
		bt.addJob(api, func(tx *Tx) error {
			chn := tx.AddChain(&nftLib.Chain{
				Name:  inSGchName,
				Table: bt.table,
			})
			bt.chains.Put(inSGchName, chn)
			bt.log.Debugf("chain '%s'/'%s' is in progress", bt.table.Name, inSGchName)
			return nil
		})
		ipVersions := []int{iplib.IP4Version, iplib.IP6Version}
		for j := range ipVersions {
			j := j
			ipV := ipVersions[j]
			bt.addJob(api, func(tx *Tx) error {
				daddrSetName := nameUtils{}.nameOfNetSet(ipV, tmpl.SgIn.Name)
				if daddrSet := bt.addrsets.At(daddrSetName); daddrSet != nil {
					input := bt.chains.At(chnFWIN)
					beginRule().
						daddr(ipV).inSet(daddrSet).
						counter().
						go2(inSGchName).applyRule(input, tx.Conn)
				}
				return nil
			})
			for k := range tmpl.Out {
				k := k
				outSG := tmpl.Out[k]
				bt.addJob(api, func(tx *Tx) error {
					saddrSetName := nameUtils{}.nameOfNetSet(ipV, outSG.Sg)
					chnApplyTo := bt.chains.At(inSGchName)
					detailsName := nameUtils{}.nameOfSG2SGRuleDetails(outSG.Proto, outSG.Sg, tmpl.SgIn.Name)
					details := bt.ruleDetails.At(detailsName)
					for n := range details.accports { //nolint:dupl
						n := n
						ports := details.accports[n]
						fin := k+1 == len(tmpl.Out) && j+1 == len(ipVersions) && n+1 == len(details.accports)
						bt.addJob(api, func(tx *Tx) error {
							if saddrSet := bt.addrsets.At(saddrSetName); saddrSet != nil {
								r := ports.S(
									ports.D(
										beginRule().saddr(ipV).inSet(saddrSet).ipProto(outSG.Proto),
									),
								).counter()
								if details.logs {
									r = r.dlogs(nfte.LogFlagsIPOpt)
								}
								r.accept().applyRule(chnApplyTo, tx.Conn)
							}
							if fin {
								r := beginRule().metaNFTRACE(tmpl.SgIn.Trace).counter()
								if tmpl.SgIn.Logs {
									r = r.dlogs(nfte.LogFlagsIPOpt)
								}
								switch da := tmpl.SgIn.DefaultAction; da {
								case model.ACCEPT:
									r = r.accept()
								case model.DROP, model.DEFAULT:
									r = r.drop()
								default:
									panic(
										errors.Errorf("for chain '%s'/'%s' provided unsupported default verdict '%v'",
											bt.table.Name, inSGchName, da),
									)
								}
								r.applyRule(chnApplyTo, tx.Conn)
								bt.log.Debugf("chain '%s'/'%s' finished",
									bt.table.Name, inSGchName)
							}
							return nil
						})
					}
					return nil
				})
			}
		}
	}
}

func (bt *batch) addFinalRules() {
	bt.addJob("final", func(tx *Tx) error {
		for _, ch := range sli(chnFWIN, chnFWOUT) {
			beginRule().drop().applyRule(bt.chains.At(ch), tx.Conn)
		}
		return nil
	})
}
