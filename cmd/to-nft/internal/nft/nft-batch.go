//go:build linux
// +build linux

package nft

import (
	"container/list"
	"context"
	"net"
	"time"

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
	chnFORWARD = "FORWARD"
	chnOUTPUT  = "OUTPUT"
	chnINPUT   = "INPUT"
	chnFWIN    = "FW-IN"
	chnFWOUT   = "FW-OUT"
)

type (
	jobItem struct {
		name string
		jobf
	}

	jobf = func(tx *nfTablesTx) error

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
		txProvider func() (*nfTablesTx, error)

		ruleDetails di.HDict[string, *ruleDetails]

		table    *nftLib.Table
		addrsets di.HDict[string, *nftLib.Set]
		chains   di.HDict[string, *nftLib.Chain]
		jobs     *list.List
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

func (bt *batch) init(table *nftLib.Table, localRules cases.LocalRules, baseRules *BaseRules) {
	bt.addrsets.Clear()
	bt.chains.Clear()
	bt.jobs = nil
	bt.table = table

	bt.initTable()
	bt.addNetSets(localRules)
	bt.initRulesDetails(localRules)
	bt.initRootChains()
	bt.initBaseRules(baseRules)
	bt.addInChains(localRules)
	bt.addOutChains(localRules)
	bt.addFinalRules()
}

func (bt *batch) addJob(n string, job jobf) {
	if bt.jobs == nil {
		bt.jobs = list.New()
	}
	bt.jobs.PushBack(jobItem{name: n, jobf: job})
}

func (bt *batch) execute(ctx context.Context, table *nftLib.Table, locals cases.LocalRules, baseRules *BaseRules) error {
	var (
		err error
		it  jobItem
		tx  *nfTablesTx
	)
	defer func() {
		if tx != nil {
			_ = tx.Close()
		}
	}()
	bt.init(table, locals, baseRules)
	bkf := backoff.ExponentialBackoffBuilder().
		WithMultiplier(1.3).                       //nolint:gomnd
		WithRandomizationFactor(0).                //nolint:gomnd
		WithMaxElapsedThreshold(20 * time.Second). //nolint:gomnd
		Build()
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
			if d <= 0 {
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

func delTables(tx *nfTablesTx, tbls ...*nftLib.Table) error {
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

func addTables(tx *nfTablesTx, tbs ...*nftLib.Table) error {
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
	bt.addJob("", func(tx *nfTablesTx) error {
		bt.log.Debugf("check and delete table '%s'", bt.table.Name)
		return delTables(tx, bt.table)
	})
	bt.addJob("", func(tx *nfTablesTx) error {
		bt.log.Debugf("add table '%s'", bt.table.Name)
		return addTables(tx, bt.table)
	})
}

func (bt *batch) initRootChains() {
	bt.addJob("init root chains", func(tx *nfTablesTx) error {
		_ = tx.AddChain(&nftLib.Chain{
			Name:     chnFORWARD,
			Table:    bt.table,
			Type:     nftLib.ChainTypeFilter,
			Policy:   val2ptr(nftLib.ChainPolicyAccept),
			Hooknum:  nftLib.ChainHookForward,
			Priority: nftLib.ChainPriorityFilter,
		})
		bt.log.Debugf("add chain '%s' into table '%s'", chnFORWARD, bt.table.Name)

		fwInChain := tx.AddChain(&nftLib.Chain{
			Name:  chnFWIN,
			Table: bt.table,
		})
		bt.log.Debugf("add chain '%s' into table '%s'", chnFWIN, bt.table.Name)
		bt.chains.Put(chnFWIN, fwInChain)
		//beginRule().metaNFTRACE(true).
		//	applyRule(fwInChain, tx.Conn)

		fwOutChain := tx.AddChain(&nftLib.Chain{
			Name:  chnFWOUT,
			Table: bt.table,
		})
		bt.log.Debugf("add chain '%s' into table '%s'", chnFWOUT, bt.table.Name)
		bt.chains.Put(chnFWOUT, fwOutChain)
		//beginRule().metaNFTRACE(true).
		//	applyRule(fwOutChain, tx.Conn)

		chnOutput := tx.AddChain(&nftLib.Chain{
			Name:     chnOUTPUT,
			Table:    bt.table,
			Type:     nftLib.ChainTypeFilter,
			Policy:   val2ptr(nftLib.ChainPolicyAccept),
			Hooknum:  nftLib.ChainHookOutput,
			Priority: nftLib.ChainPriorityFilter,
		})
		bt.log.Debugf("add chain '%s' into table '%s'", chnOUTPUT, bt.table.Name)
		bt.chains.Put(chnOUTPUT, chnOutput)
		beginRule().
			ctState(nfte.CtStateBitESTABLISHED|nfte.CtStateBitRELATED).
			accept().applyRule(chnOutput, tx.Conn)
		beginRule().oifname().neqS("lo").counter().
			go2(chnFWOUT).applyRule(chnOutput, tx.Conn)

		chnInput := tx.AddChain(&nftLib.Chain{
			Name:     chnINPUT,
			Table:    bt.table,
			Type:     nftLib.ChainTypeFilter,
			Policy:   val2ptr(nftLib.ChainPolicyAccept),
			Hooknum:  nftLib.ChainHookInput,
			Priority: nftLib.ChainPriorityFilter,
		})
		bt.log.Debugf("add chain '%s' into table '%s'", chnINPUT, bt.table.Name)
		bt.chains.Put(chnINPUT, chnInput)
		beginRule().
			ctState(nfte.CtStateBitESTABLISHED|nfte.CtStateBitRELATED).
			accept().applyRule(chnInput, tx.Conn)
		beginRule().iifname().neqS("lo").counter().
			go2(chnFWIN).applyRule(chnInput, tx.Conn)
		return nil
	})
}

func (bt *batch) initBaseRules(baseRules *BaseRules) {
	const api = "init-base-rules"

	if baseRules == nil {
		return
	}

	var nws []model.Network
	linq.From(baseRules.Nets).
		Select(func(i any) any {
			return model.Network{Net: *i.(config.NetCIDR).IPNet}
		}).ToSlice(&nws)

	for i, nw := range sli(cases.SeparateNetworks(nws)) {
		isIP4 := i == 0
		nw := nw
		elems := setsUtils{}.nets2SetElements(nw, tern(isIP4, iplib.IP4Version, iplib.IP6Version))
		if len(elems) > 0 {
			bt.addJob(api, func(tx *nfTablesTx) error {
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

func (bt *batch) addNetSets(localRules cases.LocalRules) {
	const api = "add-net-sets"

	_ = localRules.IterateNetworks(func(sgName string, nets []net.IPNet, isV6 bool) error {
		ipV := tern(isV6, iplib.IP6Version, iplib.IP4Version)
		nameOfSet := nameUtils{}.nameOfNetSet(ipV, sgName)
		if bt.addrsets.At(nameOfSet) != nil {
			return nil
		}
		if elements := (setsUtils{}).nets2SetElements(nets, ipV); len(elements) > 0 {
			bt.addJob(api, func(tx *nfTablesTx) error {
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
				bt.log.Debugf("add network(s) %s into set '%s'/'%s'",
					slice2stringer(nets...), bt.table.Name, nameOfSet)
				bt.addrsets.Put(netSet.Name, netSet)
				return nil
			})
		}
		return nil
	})
}

func (bt *batch) initRulesDetails(localRules cases.LocalRules) {
	portRange2elems := func(pr model.PortRanges) (ret [][2]model.PortNumber) {
		pr.Iterate(func(r model.PortRange) bool {
			a, b := r.Bounds()
			var x [2]model.PortNumber
			x[0], _ = a.AsIncluded().GetValue()
			x[1], _ = b.AsIncluded().GetValue()
			ret = append(ret, x)
			return true
		})
		return ret
	}
	for _, r := range localRules.AllRules() {
		item := ruleDetails{
			accports: make([]accports, 0, len(r.Ports)),
			logs:     r.Logs,
		}
		for _, p := range r.Ports {
			accp := accports{
				dp: portRange2elems(p.D),
				sp: portRange2elems(p.S),
			}
			if !(len(accp.sp) == 0 && len(accp.dp) == 0) {
				item.accports = append(item.accports, accp)
			}
		}
		if len(item.accports) == 0 {
			item.accports = append(item.accports, accports{})
		}
		setsName := nameUtils{}.nameOfPortSet(r.ID.Transport, r.ID.SgFrom, r.ID.SgTo)
		bt.ruleDetails.Put(setsName, &item)
	}
}

func (bt *batch) addOutChains(localRules cases.LocalRules) {
	const api = "make-out-chains"

	outTmpls := localRules.TemplatesOutRules()
	for i := range outTmpls {
		tmpl := outTmpls[i]
		outSGchName := chnFWOUT + "-" + tmpl.SgOut.Name
		bt.addJob(api, func(tx *nfTablesTx) error {
			chn := tx.AddChain(&nftLib.Chain{Name: outSGchName, Table: bt.table})
			bt.chains.Put(outSGchName, chn)
			bt.log.Debugf("add chain '%s' into table '%s'", outSGchName, bt.table.Name)
			return nil
		})
		cAddedRules := 0
		ipVersions := []int{iplib.IP4Version, iplib.IP6Version}
		for j := range ipVersions {
			j := j
			ipV := ipVersions[j]
			bt.addJob(api, func(tx *nfTablesTx) error {
				saddrSetName := nameUtils{}.nameOfNetSet(ipV, tmpl.SgOut.Name)
				if saddrSet := bt.addrsets.At(saddrSetName); saddrSet != nil {
					output := bt.chains.At(chnFWOUT)
					beginRule().
						saddr(ipV).inSet(saddrSet).counter().
						go2(outSGchName).applyRule(output, tx.Conn)
				}
				return nil
			})
			for k := range tmpl.In {
				k := k
				in := tmpl.In[k]
				bt.addJob(api, func(tx *nfTablesTx) error {
					daddrSetName := nameUtils{}.nameOfNetSet(ipV, in.Sg)
					chnApplyTo := bt.chains.At(outSGchName)
					detailsName := nameUtils{}.nameOfPortSet(in.Proto, tmpl.SgOut.Name, in.Sg)
					details := bt.ruleDetails.At(detailsName)
					for n := range details.accports { //nolint:dupl
						n := n
						ports := details.accports[n]
						fin := k+1 == len(tmpl.In) && j+1 == len(ipVersions) && n+1 == len(details.accports)
						bt.addJob(api, func(tx *nfTablesTx) error {
							if daddrSet := bt.addrsets.At(daddrSetName); daddrSet != nil {
								cAddedRules++
								r := ports.D(
									ports.S(
										beginRule().daddr(ipV).inSet(daddrSet).ipProto(in.Proto),
									),
								).counter()
								if details.logs {
									r = r.dlogs(nfte.LogFlagsIPOpt)
								}
								r.accept().applyRule(chnApplyTo, tx.Conn)
							}
							if fin {
								r := beginRule().metaNFTRACE(tmpl.SgOut.Trace).counter()
								if tmpl.SgOut.Logs {
									r = r.dlogs(nfte.LogFlagsIPOpt)
								}
								switch da := tmpl.SgOut.DefaultAction; da {
								case model.ACCEPT:
									r = r.accept()
								case model.DROP:
									r = r.drop()
								default:
									panic(
										errors.Errorf("in chain '%s' unrecognized default verdict action(%v)", outSGchName, da),
									)
								}
								r.applyRule(chnApplyTo, tx.Conn)
								bt.log.Debugf("added %v rule(s) to chain '%s' in table '%s'",
									cAddedRules, outSGchName, bt.table.Name)
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

func (bt *batch) addInChains(localRules cases.LocalRules) {
	const api = "make-in-chains"

	inTmpls := localRules.TemplatesInRules()
	for i := range inTmpls {
		tmpl := inTmpls[i]
		inSGchName := chnFWIN + "-" + tmpl.SgIn.Name
		bt.addJob(api, func(tx *nfTablesTx) error {
			chn := tx.AddChain(&nftLib.Chain{
				Name:  inSGchName,
				Table: bt.table,
			})
			bt.chains.Put(inSGchName, chn)
			bt.log.Debugf("add chain '%s' into table '%s'", inSGchName, bt.table.Name)
			return nil
		})
		cAddedRules := 0
		ipVersions := []int{iplib.IP4Version, iplib.IP6Version}
		for j := range ipVersions {
			j := j
			ipV := ipVersions[j]
			bt.addJob(api, func(tx *nfTablesTx) error {
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
				bt.addJob(api, func(tx *nfTablesTx) error {
					saddrSetName := nameUtils{}.nameOfNetSet(ipV, outSG.Sg)
					chnApplyTo := bt.chains.At(inSGchName)
					detailsName := nameUtils{}.nameOfPortSet(outSG.Proto, outSG.Sg, tmpl.SgIn.Name)
					details := bt.ruleDetails.At(detailsName)
					for n := range details.accports { //nolint:dupl
						n := n
						ports := details.accports[n]
						fin := k+1 == len(tmpl.Out) && j+1 == len(ipVersions) && n+1 == len(details.accports)
						bt.addJob(api, func(tx *nfTablesTx) error {
							if saddrSet := bt.addrsets.At(saddrSetName); saddrSet != nil {
								cAddedRules++
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
								case model.DROP:
									r = r.drop()
								default:
									panic(
										errors.Errorf("in chain '%s' unrecognized default verdict action(%v)", inSGchName, da),
									)
								}
								r.applyRule(chnApplyTo, tx.Conn)
								bt.log.Debugf("added %v rule(s) to chain '%s' in table '%s'",
									cAddedRules, inSGchName, bt.table.Name)
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
	bt.addJob("final", func(tx *nfTablesTx) error {
		for _, ch := range sli(chnFWIN, chnFWOUT) {
			beginRule().drop().applyRule(bt.chains.At(ch), tx.Conn)
		}
		return nil
	})
}
