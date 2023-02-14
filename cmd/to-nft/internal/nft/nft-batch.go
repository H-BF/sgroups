package nft

import (
	"container/list"
	"math"
	"net"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/logger"
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

type (
	jobItem struct {
		name string
		jobf
	}

	jobf = func(tx *nfTablesTx) error

	batch struct {
		table  *nftLib.Table
		sets   dict[string, *nftLib.Set]
		chains dict[string, *nftLib.Chain]

		jobs *list.List
		log  logger.TypeOfLogger
	}
)

func (bt *batch) init(table *nftLib.Table, locals cases.LocalRules) {
	bt.sets.clear()
	bt.chains.clear()
	bt.table = table

	bt.addJob("", func(tx *nfTablesTx) error {
		bt.log.Debugf("check and delete table '%s'", table.Name)
		return delTables(tx, table)
	})
	bt.addJob("", func(tx *nfTablesTx) error {
		bt.log.Debugf("add table '%s'", table.Name)
		return addTables(tx, table)
	})
	bt.addJob("init root chains", func(tx *nfTablesTx) error {
		_ = tx.AddChain(&nftLib.Chain{
			Name:     chnFORWARD,
			Table:    table,
			Type:     nftLib.ChainTypeFilter,
			Policy:   val2ptr(nftLib.ChainPolicyAccept),
			Hooknum:  nftLib.ChainHookForward,
			Priority: nftLib.ChainPriorityFilter,
		})
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnFORWARD)

		fwInChain := tx.AddChain(&nftLib.Chain{
			Name:  chnFWIN,
			Table: table,
		})
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnFWIN)
		bt.chains.put(chnFWIN, fwInChain)
		beginRule().metaNFTRACE(true).
			applyRule(fwInChain, tx.Conn)

		fwOutChain := tx.AddChain(&nftLib.Chain{
			Name:  chnFWOUT,
			Table: table,
		})
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnFWOUT)
		bt.chains.put(chnFWOUT, fwOutChain)
		beginRule().metaNFTRACE(true).
			applyRule(fwOutChain, tx.Conn)

		chnOutput := tx.AddChain(&nftLib.Chain{
			Name:     chnOUTPUT,
			Table:    table,
			Type:     nftLib.ChainTypeFilter,
			Policy:   val2ptr(nftLib.ChainPolicyAccept),
			Hooknum:  nftLib.ChainHookOutput,
			Priority: nftLib.ChainPriorityFilter,
		})
		bt.log.Debugf("add chain '%s'/'%s'", bt.table.Name, chnOUTPUT)
		bt.chains.put(chnOUTPUT, chnOutput)
		beginRule().oifname().neqS("lo").counter().
			go2(chnFWOUT).applyRule(chnOutput, tx.Conn)

		chnInput := tx.AddChain(&nftLib.Chain{
			Name:     chnINPUT,
			Table:    table,
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
	bt.addPortSets(locals)
	bt.addNetSets(locals)
	bt.addOutChains(locals)
	bt.addInChains(locals)
	bt.finalSteps()
}

func (bt *batch) addJob(n string, job jobf) {
	if bt.jobs == nil {
		bt.jobs = list.New()
	}
	bt.jobs.PushBack(jobItem{name: n, jobf: job})
}

func (bt *batch) execute(tx *nfTablesTx, table *nftLib.Table, locals cases.LocalRules) error {
	bt.init(table, locals)
	var err error
	var it jobItem
	for el := bt.jobs.Front(); el != nil; el = bt.jobs.Front() {
		bt.jobs.Remove(el)
		it = el.Value.(jobItem)
		if err = it.jobf(tx); err == nil {
			err = tx.Flush()
		}
		if err != nil {
			break
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

func (bt *batch) addNetSets(locals cases.LocalRules) {
	const (
		api  = "add-net-sets"
		b32  = 32
		b128 = 128
	)

	_ = locals.IterateNetworks(func(sgName string, nets []net.IPNet, isV6 bool) error {
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
				elements = append(elements, nftLib.SetElement{
					Key:    nw.IP,
					KeyEnd: ipLast,
				})
			case iplib.IP6Version:
				if ones < b128 {
					ipLast = iplib.NextIP(ipLast)
				}
				elements = append(elements, nftLib.SetElement{
					Key:    nw.IP,
					KeyEnd: ipLast,
				})
			}
		}
		if len(elements) > 0 {
			bt.addJob(api, func(tx *nfTablesTx) error {
				netSet := &nftLib.Set{
					Table:    bt.table,
					KeyType:  ty,
					Interval: true,
					Name:     nameOfSet,
				}
				if err := tx.AddSet(netSet, elements); err != nil {
					return err
				}
				bt.log.Debugf("add network(s) set '%s'/'%s'%s",
					bt.table.Name, nameOfSet, nets)
				bt.sets.put(netSet.Name, netSet)
				return nil
			})
		}
		return nil
	})
}

func (bt *batch) addPortSets(rules cases.LocalRules) {
	const api = "add-port-sets"

	apply := func(nameOfSet string, pr model.PortRanges) {
		bt.addJob(api, func(tx *nfTablesTx) error {
			var (
				be      = nftLibUtil.BigEndian
				elemnts []nftLib.SetElement
				err     error
			)
			pr.Iterate(func(r model.PortRange) bool {
				a, b := r.Bounds()
				b = b.AsExcluded()
				aVal, _ := a.GetValue()
				bVal, _ := b.GetValue()
				if aVal > math.MaxUint16 || bVal > math.MaxUint16 {
					err = ErrPortRange
					return false //error
				}
				elemnts = append(elemnts,
					nftLib.SetElement{
						Key:    be.PutUint16(uint16(aVal)),
						KeyEnd: be.PutUint16(uint16(bVal)),
					},
				)
				return true
			})
			if err != nil {
				return err
			}
			if len(elemnts) > 0 {
				portSet := &nftLib.Set{
					Table:    bt.table,
					Name:     nameOfSet,
					KeyType:  nftLib.TypeInetService,
					Interval: true,
				}
				if err = tx.AddSet(portSet, elemnts); err != nil {
					return err
				}
				bt.log.Debugf("add port(s) set '%s'/%s'%s",
					bt.table.Name, nameOfSet, pr)
				bt.sets.put(nameOfSet, portSet)
			}
			return nil
		})
	}
	for sgFrom, to := range rules.SgRules {
		for sgTo, ports := range to {
			name := nameUtils{}.nameOfPortSet(
				sgFrom.Transport, sgFrom.SgName, sgTo, false,
			)
			apply(name, ports.From)
			name = nameUtils{}.nameOfPortSet(
				sgFrom.Transport, sgFrom.SgName, sgTo, true,
			)
			apply(name, ports.To)
		}
	}
}

func (bt *batch) addOutChains(rules cases.LocalRules) {
	const api = "make-out-chains"

	var names nameUtils
	_ = rules.TemplatesOut(func(outSG string, inSGs []string) error {
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
		ipVers := []int{iplib.IP4Version, iplib.IP6Version}
		for i := range ipVers {
			ipV := ipVers[i]
			bt.addJob(api, func(tx *nfTablesTx) error {
				saddr := names.nameOfNetSet(ipV, outSG)
				saddrSet := bt.sets.at(saddr)
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
				}
				return nil
			})
			for j := range inSGs {
				inSG := inSGs[j]
				tps := []model.NetworkTransport{model.TCP, model.UDP}
				for k := range tps {
					tr := tps[k]
					bt.addJob(api, func(tx *nfTablesTx) error {
						daddr := names.nameOfNetSet(ipV, inSG)
						sport := names.nameOfPortSet(tr, outSG, inSG, false)
						dport := names.nameOfPortSet(tr, outSG, inSG, true)
						sportSet := bt.sets.at(sport)
						dportSet := bt.sets.at(dport)
						daddrSet := bt.sets.at(daddr)
						if daddrSet == nil {
							return nil
						}
						chn := bt.chains.at(outSGchName)
						switch ipV {
						case iplib.IP4Version:
							bt.log.Debugf("apply %s-rule(s) to chain '%s'/'%s'",
								tr, bt.table.Name, outSGchName)
							b := beginRule().
								ipProto(tr).daddr4().inSet(daddrSet)
							if dportSet != nil {
								b = b.ipProto(tr).dport().inSet(dportSet)
							}
							if sportSet != nil {
								b = b.ipProto(tr).sport().inSet(sportSet)
							}
							b.counter().accept().
								applyRule(chn, tx.Conn)
						case iplib.IP6Version:
							// TODO: to impl in future
						}
						return nil
					})
				}
			}
		}
		return nil
	})
}

func (bt *batch) addInChains(rules cases.LocalRules) {
	const api = "make-in-chains"

	var names nameUtils
	_ = rules.TemplatesIn(func(outSGs []string, inSG string) error {
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
				} else {
					beginRule().drop().applyRule(ch, tx.Conn)
				}
				return nil
			})
		}()
		ipVers := []int{iplib.IP4Version, iplib.IP6Version}
		for i := range ipVers {
			ipV := ipVers[i]
			bt.addJob(api, func(tx *nfTablesTx) error {
				daddr := names.nameOfNetSet(ipV, inSG)
				daddrSet := bt.sets.at(daddr)
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
						saddr := names.nameOfNetSet(ipV, outSG)
						sport := names.nameOfPortSet(tr, outSG, inSG, false)
						dport := names.nameOfPortSet(tr, outSG, inSG, true)
						sportSet := bt.sets.at(sport)
						dportSet := bt.sets.at(dport)
						saddrSet := bt.sets.at(saddr)
						if saddrSet == nil {
							return nil
						}
						chn := bt.chains.at(inSGchName)
						switch ipV {
						case iplib.IP4Version:
							bt.log.Debugf("apply %s-rule(s) to chain '%s'/'%s'",
								tr, bt.table.Name, inSGchName)
							b := beginRule().
								ipProto(tr).saddr4().inSet(saddrSet)
							if sportSet != nil {
								b = b.ipProto(tr).sport().inSet(sportSet)
							}
							if dportSet != nil {
								b = b.ipProto(tr).dport().inSet(dportSet)
							}
							b.counter().accept().
								applyRule(chn, tx.Conn)
						case iplib.IP6Version:
							// TODO: to impl in future
						}
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
		beginRule().drop().
			applyRule(bt.chains.at(chnFWIN), tx.Conn)
		beginRule().drop().
			applyRule(bt.chains.at(chnFWOUT), tx.Conn)
		return nil
	})
}
