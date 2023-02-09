package nft

import (
	"math"
	"net"
	"sync"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/c-robinson/iplib"
	nftLib "github.com/google/nftables"
	nftLibUtil "github.com/google/nftables/binaryutil"
	"github.com/pkg/errors"
	"github.com/vishvananda/netns"
)

type nfTablesTx struct {
	*nftLib.Conn
	commitOnce sync.Once
}

type generatedSets map[string]*nftLib.Set

func nfTx(netNS string) (*nfTablesTx, error) {
	const api = "open nft tx"

	opts := []nftLib.ConnOption{nftLib.AsLasting()}
	if len(netNS) > 0 {
		n, e := netns.GetFromName(netNS)
		if e != nil {
			return nil, errors.WithMessagef(e,
				"%s: accessing netns '%s'", api, netNS)
		}
		opts = append(opts, nftLib.WithNetNSFd(int(n)))
		defer n.Close()
	}
	c, e := nftLib.New(opts...)
	if e != nil {
		return nil, errors.WithMessage(e, api)
	}
	return &nfTablesTx{Conn: c}, nil
}

func (tx *nfTablesTx) applyNetSets(tbl *nftLib.Table, locals cases.LocalRules) (generatedSets, error) {
	const (
		api  = "ntf/apply-net-sets"
		b32  = 32
		b128 = 128
	)
	gn := make(generatedSets)
	e := locals.IterateNetworks(func(sgName string, nets []net.IPNet, isV6 bool) error {
		ipV := iplib.IP4Version
		ty := nftLib.TypeIPAddr
		if isV6 {
			ipV = iplib.IP6Version
			ty = nftLib.TypeIP6Addr
		}
		nameOfSet := nameUtils{}.nameOfNetSet(ipV, sgName)
		if gn[nameOfSet] != nil {
			return nil
		}
		var elements []nftLib.SetElement
		for _, nw := range nets {
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
			netSet := &nftLib.Set{
				Table:    tbl,
				KeyType:  ty,
				Interval: true,
				Name:     nameOfSet,
			}
			if err := tx.AddSet(netSet, elements); err != nil {
				return errors.WithMessagef(err, "%s: add set", api)
			}
			gn[nameOfSet] = netSet
		}
		return nil
	})
	return gn, e
}

func (tx *nfTablesTx) applyPortSets(tbl *nftLib.Table, rules cases.LocalRules) (generatedSets, error) {
	const api = "ntf/apply-port-sets"

	gn := make(generatedSets)

	apply := func(nameOfSet string, pr model.PortRanges) error {
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
			return errors.WithMessage(err, api)
		}
		if len(elemnts) > 0 {
			portSet := &nftLib.Set{
				Table:    tbl,
				Name:     nameOfSet,
				KeyType:  nftLib.TypeInetService,
				Interval: true,
			}
			if err = tx.AddSet(portSet, elemnts); err != nil {
				return errors.WithMessagef(err, "%s: add set", api)
			}
			gn[nameOfSet] = portSet
		}
		return nil
	}

	for sgFrom, to := range rules.SgRules {
		for sgTo, ports := range to {
			name := nameUtils{}.nameOfPortSet(
				sgFrom.Transport, sgFrom.SgName, sgTo, false,
			)
			if err := apply(name, ports.From); err != nil {
				return gn, err
			}
			name = nameUtils{}.nameOfPortSet(
				sgFrom.Transport, sgFrom.SgName, sgTo, true,
			)
			if err := apply(name, ports.To); err != nil {
				return gn, err
			}
		}
	}
	return gn, nil
}

func (tx *nfTablesTx) fillWithOutRules(chn *nftLib.Chain, rules cases.LocalRules, tcpudp *nftLib.Set, nets, ports generatedSets) error {
	const api = "nft/fill-chain-with-out-rules"

	var names nameUtils
	addrC := make(map[string]int)
	e := rules.TemplatesOut(func(tr model.NetworkTransport, out string, in []string) error {
		var outChainUsed bool
		outChain := tx.AddChain(&nftLib.Chain{
			Name:  "FW-OUT-" + out,
			Table: chn.Table,
		})
		defer func() {
			if !outChainUsed {
				tx.DelChain(outChain)
			} else {
				beginRule().drop().applyRule(outChain, tx.Conn)
			}
		}()
		for i := range in {
			sport := names.nameOfPortSet(tr, out, in[i], false)
			dport := names.nameOfPortSet(tr, out, in[i], true)
			sportSet := ports[sport]
			dportSet := ports[dport]
			if !(sportSet != nil && dportSet != nil) {
				continue
			}
			for _, ipV := range []int{iplib.IP4Version, iplib.IP6Version} {
				saddr := names.nameOfNetSet(ipV, out)
				daddr := names.nameOfNetSet(ipV, in[i])
				saddrSet := nets[saddr]
				daddrSet := nets[daddr]
				if !(saddrSet != nil && daddrSet != nil) {
					continue
				}
				addrC[saddr]++
				addrC[daddr]++
				switch ipV {
				case iplib.IP4Version:
					outChainUsed = true
					if addrC[saddr] == 1 {
						beginRule().
							saddr4().inSet(saddrSet).
							counter().
							go2(outChain.Name).applyRule(chn, tx.Conn)
					}
					if addrC[daddr] == 1 {
						beginRule().
							metaL4PROTO().inSet(tcpudp).
							daddr4().inSet(daddrSet).
							metaNFTRACE(true).applyRule(outChain, tx.Conn)
					}
					beginRule().
						ipProto(tr).daddr4().inSet(daddrSet).
						ipProto(tr).dport().inSet(dportSet).
						ipProto(tr).sport().inSet(sportSet).
						counter().
						accept().
						applyRule(outChain, tx.Conn)
				case iplib.IP6Version:
					// TODO: to impl in future
				}
			}
		}
		return nil
	})
	return errors.WithMessage(e, api)
}

func (tx *nfTablesTx) fillWithInRules(chn *nftLib.Chain, rules cases.LocalRules, tcpudp *nftLib.Set, nets, ports generatedSets) error {
	const api = "nft/fill-chain-with-in-rules"

	saddrC := make(map[string]int)
	daddrC := make(map[string]int)
	var names nameUtils
	e := rules.TemplatesIn(func(tr model.NetworkTransport, out []string, in string) error {
		for i := range out {
			sport := names.nameOfPortSet(tr, out[i], in, false)
			dport := names.nameOfPortSet(tr, out[i], in, true)
			sportSet := ports[sport]
			dportSet := ports[dport]
			if !(sportSet != nil && dportSet != nil) {
				continue
			}
			for _, ipV := range []int{iplib.IP4Version, iplib.IP6Version} {
				saddr := names.nameOfNetSet(ipV, out[i])
				daddr := names.nameOfNetSet(ipV, in)
				saddrSet := nets[saddr]
				daddrSet := nets[daddr]
				if saddrSet != nil {
					saddrC[saddr]++
				}
				if daddrSet != nil {
					daddrC[daddr]++
				}
				if !(saddrSet != nil && daddrSet != nil) {
					continue
				}
				switch ipV {
				case iplib.IP4Version:
				case iplib.IP6Version:
					// TODO: to impl in future
				}
			}
		}
		return nil
	})

	return errors.WithMessage(e, api)
}

func (tx *nfTablesTx) deleteTables(tbs ...*nftLib.Table) error {
	const api = "ntf/del-tables"

	if len(tbs) == 0 {
		return nil
	}
	type key = struct {
		Fam  nftLib.TableFamily
		Name string
	}
	index := make(map[key]struct{})
	for i := range tbs {
		index[key{tbs[i].Family, tbs[i].Name}] = struct{}{}
	}

	tableList, err := tx.ListTables()
	if err != nil {
		return errors.WithMessagef(err, "%s: get list of tables", api)
	}
	for _, tbl := range tableList {
		k := key{tbl.Family, tbl.Name}
		if _, found := index[k]; found {
			tx.DelTable(tbl)
			delete(index, k)
		}
	}
	return nil
}

func (tx *nfTablesTx) commit() error {
	const api = "ntf/flush"

	c := tx.Conn
	var err error
	var passed bool
	tx.commitOnce.Do(func() {
		err = c.Flush()
		_ = c.CloseLasting()
		passed = true
	})
	if passed {
		return errors.WithMessage(err, api)
	}
	return errors.Errorf("%s: commit on closed", api)
}

func (tx *nfTablesTx) abort() {
	c := tx.Conn
	tx.commitOnce.Do(func() {
		_ = c.CloseLasting()
	})
}

var (
	_ = ipToReverseBytes
)

func reverseBytes(p []byte) {
	for i, j := 0, len(p)-1; i < j && j >= 0; i, j = i+1, j-1 {
		p[i], p[j] = p[j], p[i]
	}
}

func ipToReverseBytes(ip net.IP) []byte {
	ipAsInt := iplib.IPToBigint(ip)
	b := ipAsInt.Bytes()
	reverseBytes(b)
	return b
}
