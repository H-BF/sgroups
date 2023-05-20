//go:build linux
// +build linux

package nft

import (
	"container/list"
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/backoff"
	"github.com/c-robinson/iplib"
	nftLib "github.com/google/nftables"
	nftLibUtil "github.com/google/nftables/binaryutil"
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

const ( //TODO: it just for testing purpose
	FWINS_ACCEPT = "ACCEPT_FWINS"
)

type (
	jobItem struct {
		name string
		jobf
	}

	jobf = func(tx *nfTablesTx) error

	accports struct {
		s  *nftLib.Set
		d  *nftLib.Set
		sp *[2]model.PortNumber
		dp *[2]model.PortNumber
	}

	batch struct {
		log        logger.TypeOfLogger
		txProvider func() (*nfTablesTx, error)

		table   *nftLib.Table
		rules   cases.LocalRules
		sets    dict[string, *nftLib.Set]
		portset dict[string, []accports]
		chains  dict[string, *nftLib.Chain]
		jobs    *list.List
	}
)

func (ap accports) S(rb ruleBuilder) ruleBuilder {
	p := ap.sp
	if p == nil {
		return rb
	}
	if p[0] == p[1] {
		return rb.eqU16(p[0])
	}
	return rb.geU16(p[0]).leU16(p[1])
}

func (ap accports) D(rb ruleBuilder) ruleBuilder {
	p := ap.dp
	if p == nil {
		return rb
	}
	if p[0] == p[1] {
		return rb.eqU16(p[0])
	}
	return rb.geU16(p[0]).leU16(p[1])
}

func (bt *batch) init(table *nftLib.Table, localRules cases.LocalRules) {
	bt.sets.clear()
	bt.chains.clear()
	bt.jobs = nil
	bt.table = table
	bt.rules = localRules

	bt.initTable()
	bt.addNetSets()
	//bt.addPortSets()
	bt.initPortSets()
	bt.initRootChains()
	bt.addOutChains()
	if false {
		bt.addInChains()
		bt.finalSteps()
	}
}

func (bt *batch) addJob(n string, job jobf) {
	if bt.jobs == nil {
		bt.jobs = list.New()
	}
	bt.jobs.PushBack(jobItem{name: n, jobf: job})
}

func (bt *batch) execute(ctx context.Context, table *nftLib.Table, locals cases.LocalRules) error {
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
	bt.init(table, locals)
	bkf := backoff.ExponentialBackoffBuilder().
		WithMultiplier(1.3).
		WithRandomizationFactor(0).
		WithMaxElapsedThreshold(20 * time.Second).
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

	type tableKey struct {
		family nftLib.TableFamily
		name   string
	}
	if len(tbls) == 0 {
		return nil
	}
	var toDel dict[tableKey, *nftLib.Table]
	for _, tbl := range tbls {
		toDel.put(tableKey{tbl.Family, tbl.Name}, tbl)
	}
	tableList, err := tx.ListTables()
	if err != nil {
		return errors.WithMessagef(err, "%s: get list of tables", api)
	}
	for _, tbl := range tableList {
		k := tableKey{tbl.Family, tbl.Name}
		if _, found := toDel.get(k); found {
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
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnFORWARD)

		fwInChain := tx.AddChain(&nftLib.Chain{
			Name:  chnFWIN,
			Table: bt.table,
		})
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnFWIN)
		bt.chains.put(chnFWIN, fwInChain)
		beginRule().metaNFTRACE(true).
			applyRule(fwInChain, tx.Conn)

		fwOutChain := tx.AddChain(&nftLib.Chain{
			Name:  chnFWOUT,
			Table: bt.table,
		})
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnFWOUT)
		bt.chains.put(chnFWOUT, fwOutChain)
		beginRule().metaNFTRACE(true).
			applyRule(fwOutChain, tx.Conn)

		chnOutput := tx.AddChain(&nftLib.Chain{
			Name:     chnOUTPUT,
			Table:    bt.table,
			Type:     nftLib.ChainTypeFilter,
			Policy:   val2ptr(nftLib.ChainPolicyAccept),
			Hooknum:  nftLib.ChainHookOutput,
			Priority: nftLib.ChainPriorityFilter,
		})
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnOUTPUT)
		bt.chains.put(chnOUTPUT, chnOutput)
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
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnINPUT)
		bt.chains.put(chnINPUT, chnInput)
		beginRule().
			ctState(nfte.CtStateBitESTABLISHED|nfte.CtStateBitRELATED).
			accept().applyRule(chnInput, tx.Conn)
		beginRule().iifname().neqS("lo").counter().
			go2(chnFWIN).applyRule(chnInput, tx.Conn)
		return nil
	})
}

func (bt *batch) addNetSets() {
	const (
		api  = "add-net-sets"
		b32  = 32
		b128 = 128
	)

	_ = bt.rules.IterateNetworks(func(sgName string, nets []net.IPNet, isV6 bool) error {
		ipV := iplib.IP4Version
		ty := nftLib.TypeIPAddr
		if isV6 {
			ipV = iplib.IP6Version
			ty = nftLib.TypeIP6Addr
		}
		nameOfSet := nameUtils{}.nameOfNetSet(ipV, sgName)
		if bt.sets.at(nameOfSet) != nil {
			return nil
		}
		var elements []nftLib.SetElement
		for i := range nets {
			nw := nets[i]
			ones, _ := nw.Mask.Size()
			netIf := iplib.NewNet(nw.IP, ones)
			ipLast := iplib.NextIP(netIf.LastAddress())
			switch ipV {
			case iplib.IP4Version:
				if ones < b32 {
					ipLast = iplib.NextIP(ipLast)
				}
			case iplib.IP6Version:
				if ones < b128 {
					ipLast = iplib.NextIP(ipLast)
				}
			}
			/*//TODO: need expert opinion
			elements = append(elements, nftLib.SetElement{
				Key:    nw.IP,
				KeyEnd: ipLast,
			})
			*/
			elements = append(elements,
				nftLib.SetElement{
					Key: nw.IP,
				},
				nftLib.SetElement{
					IntervalEnd: true,
					Key:         ipLast,
				})
		}
		if len(elements) > 0 {
			bt.addJob(api, func(tx *nfTablesTx) error {
				netSet := &nftLib.Set{
					ID:       nextSetID(),
					Constant: true,
					Table:    bt.table,
					KeyType:  ty,
					Interval: true,
					Name:     nameOfSet,
				}
				if err := tx.AddSet(netSet, elements); err != nil {
					return err
				}
				bt.log.Debugf("add network(s) %s into set '%s'/'%s'",
					slice2stringer(nets...), bt.table.Name, nameOfSet)
				bt.sets.put(netSet.Name, netSet)
				return nil
			})
		}
		return nil
	})
}

func (bt *batch) addPortSets() { //TODO: Refactor
	const api = "add-port-sets"

	portRange2nftElems := func(pr model.PortRange) (ret []nftLib.SetElement) {
		if !(pr == nil || pr.IsNull()) {
			be := nftLibUtil.BigEndian
			a, b := pr.Bounds()
			left, _ := a.AsIncluded().GetValue()
			right, _ := b.AsExcluded().GetValue()
			ret = append(ret, nftLib.SetElement{
				Key: be.PutUint16(left),
			})
			if a.Cmp(b) != 0 {
				ret = append(ret, nftLib.SetElement{
					Key:         be.PutUint16(right),
					IntervalEnd: true,
				})
			}
		}
		return ret
	}
	for sgFrom, to := range bt.rules.SgRules {
		for sgTo, ports := range to {
			sgTo := sgTo
			ports := ports
			sgFrom := sgFrom
			bt.addJob(api, func(tx *nfTablesTx) error {
				var pts []accports
				setsName := nameUtils{}.nameOfPortSet(sgFrom.Transport, sgFrom.SgName, sgTo)
				for i, p := range ports {
					var accp accports
					if elms := portRange2nftElems(p.S); len(elms) > 0 {
						accp.s = &nftLib.Set{
							ID:        nextSetID(),
							Anonymous: true,
							Table:     bt.table,
							Name:      fmt.Sprintf("s:%s:%v", setsName, i),
							Constant:  true,
							KeyType:   nftLib.TypeInetService,
							Interval:  len(elms) > 1,
						}
						if e := tx.AddSet(accp.s, elms); e != nil {
							return e
						}
					}
					if elms := portRange2nftElems(p.D); len(elms) > 0 {
						accp.d = &nftLib.Set{
							ID:        nextSetID(),
							Anonymous: true,
							Table:     bt.table,
							Name:      fmt.Sprintf("d:%s:%v", setsName, i),
							Constant:  true,
							KeyType:   nftLib.TypeInetService,
							Interval:  len(elms) > 1,
						}
						if e := tx.AddSet(accp.d, elms); e != nil {
							return e
						}
					}
					if !(accp.s == nil && accp.d == nil) {
						pts = append(pts, accp)
					}
				}
				if len(pts) == 0 {
					pts = append(pts, accports{})
				} else {
					bt.log.Debugf("add port set(s) '%s' into table '%s'", setsName, bt.table.Name)
				}
				bt.portset.put(setsName, pts)
				return nil
			})
		}
	}
}

func (bt *batch) initPortSets() {
	portRange2elems := func(pr model.PortRange) (ret *[2]model.PortNumber) {
		if !(pr == nil || pr.IsNull()) {
			ret = new([2]model.PortNumber)
			a, b := pr.Bounds()
			ret[0], _ = a.AsIncluded().GetValue()
			ret[1], _ = b.AsIncluded().GetValue()
		}
		return ret
	}
	for sgFrom, to := range bt.rules.SgRules {
		for sgTo, ports := range to {
			var pts []accports
			setsName := nameUtils{}.nameOfPortSet(sgFrom.Transport, sgFrom.SgName, sgTo)
			for _, p := range ports {
				accp := accports{
					dp: portRange2elems(p.D),
					sp: portRange2elems(p.S),
				}
				if !(accp.sp == nil && accp.dp == nil) {
					pts = append(pts, accp)
				}
			}
			if len(pts) == 0 {
				pts = append(pts, accports{})
			}
			bt.portset.put(setsName, pts)
		}
	}
}

func (bt *batch) addOutChains() {
	const api = "make-out-chains"

	var names nameUtils
	_ = bt.rules.TemplatesOut(func(outSG string, inSGs []string) error {
		var outChainUsed bool
		outSGchName := chnFWOUT + "-" + outSG
		bt.addJob(api, func(tx *nfTablesTx) error {
			chn := tx.AddChain(&nftLib.Chain{
				Name:  outSGchName,
				Table: bt.table,
			})
			bt.chains.put(outSGchName, chn)
			bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, outSGchName)
			return nil
		})
		defer func() {
			bt.addJob(api, func(tx *nfTablesTx) error {
				ch := bt.chains.at(outSGchName)
				if !outChainUsed {
					tx.DelChain(ch)
					bt.log.Debugf("delete chain '%s'/'%s'", bt.table.Name, outSGchName)
				} else {
					beginRule().drop().applyRule(ch, tx.Conn)
				}
				return nil
			})
		}()

		for _, ipV := range []int{iplib.IP4Version, iplib.IP6Version} {
			ipV := ipV
			bt.addJob(api, func(tx *nfTablesTx) error {
				saddrSetName := names.nameOfNetSet(ipV, outSG)
				saddrSet := bt.sets.at(saddrSetName)
				if saddrSet == nil {
					return nil
				}
				output := bt.chains.at(chnFWOUT)
				switch ipV {
				case iplib.IP4Version:
					outChainUsed = true
					beginRule().
						saddr4().inSet(saddrSet).
						counter().
						go2(outSGchName).applyRule(output, tx.Conn)
				case iplib.IP6Version:
					// TODO: to impl in future
					fallthrough
				default:
					panic("UB")
				}
				return nil
			})
			for _, inSG := range inSGs {
				inSG := inSG
				for _, tr := range []model.NetworkTransport{model.TCP, model.UDP} {
					tr := tr
					bt.addJob(api, func(tx *nfTablesTx) error {
						daddrSetName := names.nameOfNetSet(ipV, inSG)
						daddrSet := bt.sets.at(daddrSetName)
						if daddrSet == nil {
							return nil
						}
						chnApplyTo := bt.chains.at(outSGchName)
						portSetsName := names.nameOfPortSet(tr, outSG, inSG)
						portSets := bt.portset.at(portSetsName)
						for _, ps := range portSets {
							b := beginRule()
							switch ipV {
							case iplib.IP4Version:
								b = b.ipProto(tr).daddr4().inSet(daddrSet)
							case iplib.IP6Version:
								// TODO: to impl in future
								fallthrough
							default:
								panic("UB")
							}
							b = ps.S(b)
							b = ps.D(b)
							b.counter().accept().
								applyRule(chnApplyTo, tx.Conn)
						}
						bt.log.Debugf("add '%s' rule to chain '%s'/'%s'",
							tr, bt.table.Name, outSGchName)
						return nil
					})
				}
			}
		}
		return nil
	})
}

func (bt *batch) addInChains() {
	const api = "make-in-chains"

	var names nameUtils
	_ = bt.rules.TemplatesIn(func(outSGs []string, inSG string) error {
		var inChainUsed bool
		inSGchName := chnFWIN + "-" + inSG
		bt.addJob(api, func(tx *nfTablesTx) error {
			chn := tx.AddChain(&nftLib.Chain{
				Name:  inSGchName,
				Table: bt.table,
			})
			bt.chains.put(inSGchName, chn)
			bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, inSGchName)
			return nil
		})
		defer func() {
			bt.addJob(api, func(tx *nfTablesTx) error {
				ch := bt.chains.at(inSGchName)
				if !inChainUsed {
					tx.DelChain(ch)
					bt.log.Debugf("delete chain '%s'/'%s'",
						bt.table.Name, inSGchName)
				} else if len(os.Getenv(FWINS_ACCEPT)) == 0 {
					beginRule().drop().applyRule(ch, tx.Conn)
				}
				return nil
			})
		}()
		ipVers := []int{iplib.IP4Version, iplib.IP6Version}
		for i := range ipVers {
			ipV := ipVers[i]
			bt.addJob(api, func(tx *nfTablesTx) error {
				daddrSetName := names.nameOfNetSet(ipV, inSG)
				daddrSet := bt.sets.at(daddrSetName)
				if daddrSet == nil {
					return nil
				}
				input := bt.chains.at(chnFWIN)
				switch ipV {
				case iplib.IP4Version:
					inChainUsed = true
					beginRule().
						daddr4().inSet(daddrSet).
						counter().
						go2(inSGchName).applyRule(input, tx.Conn)
				case iplib.IP6Version:
					// TODO: to impl in future
				}
				return nil
			})
			for j := range outSGs {
				outSG := outSGs[j]
				tps := []model.NetworkTransport{model.TCP, model.UDP}
				for k := range tps {
					tr := tps[k]
					bt.addJob(api, func(tx *nfTablesTx) error {
						saddrSetName := names.nameOfNetSet(ipV, outSG)
						saddrSet := bt.sets.at(saddrSetName)
						if saddrSet == nil {
							return nil
						}
						chnApplyTo := bt.chains.at(inSGchName)
						portSetsName := names.nameOfPortSet(tr, outSG, inSG)
						portSets := bt.portset.at(portSetsName)
						for i := range portSets {
							switch ipV {
							case iplib.IP4Version:
								b := beginRule().
									ipProto(tr).saddr4().inSet(saddrSet)
								if d := portSets[i].d; d != nil {
									b = b.ipProto(tr).dport().inSet(d)
								}
								if s := portSets[i].s; s != nil {
									b = b.ipProto(tr).sport().inSet(s)
								}
								b.counter().accept().
									applyRule(chnApplyTo, tx.Conn)
							case iplib.IP6Version:
								// TODO: to impl in future
							default:
								panic("UB")
							}
						}
						bt.log.Debugf("add '%s' rule to chain '%s'/'%s'",
							tr, bt.table.Name, inSGchName)
						return nil
					})
				}
			}
		}
		return nil
	})
}

func (bt *batch) finalSteps() {
	bt.addJob("final", func(tx *nfTablesTx) error {
		if len(os.Getenv(FWINS_ACCEPT)) == 0 {
			beginRule().drop().
				applyRule(bt.chains.at(chnFWIN), tx.Conn)
		}
		beginRule().drop().
			applyRule(bt.chains.at(chnFWOUT), tx.Conn)
		return nil
	})
}
