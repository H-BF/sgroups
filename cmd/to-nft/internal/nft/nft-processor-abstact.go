package nft

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	"github.com/H-BF/sgroups/internal/config"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	nftlib "github.com/google/nftables"

	"github.com/c-robinson/iplib"
	uuid "github.com/satori/go.uuid"
)

type (
	// AppliedRules -
	AppliedRules struct {
		ID          uuid.UUID
		NetNS       string
		TargetTable string
		BaseRules   BaseRules
		LocalData   cases.LocalData
	}

	// Patch -
	Patch interface {
		String() string
		Appply(context.Context, *AppliedRules) error
		isAppliedRulesPatch()
	}

	// UpdateFqdnNetsets - is kind of Patch
	UpdateFqdnNetsets struct {
		IPVersion int
		TTL       time.Duration
		FQDN      model.FQDN
		Addresses []net.IP
	}

	// NfTablesProcessorOpt constructor option(s)
	NfTablesProcessorOpt interface {
		isNfTablesProcessorOpt()
	}

	// NfTablesProcessor abstract interface
	NfTablesProcessor interface {
		ApplyConf(ctx context.Context, data cases.LocalData) (AppliedRules, error)
		Close() error
	}

	// WithNetNS use network namespace
	WithNetNS struct {
		NetNS string
	}

	// BaseRules -
	BaseRules struct {
		Nets []config.NetCIDR
	}
)

// LastAppliedRules -
func LastAppliedRules(netNS string) *AppliedRules {
	lastAppliedRulesMx.RLock()
	defer lastAppliedRulesMx.RUnlock()
	return lastAppliedRules.At(netNS)
}

// LastAppliedRulesUpd -
func LastAppliedRulesUpd(netNS string, data *AppliedRules) {
	lastAppliedRulesMx.Lock()
	defer lastAppliedRulesMx.Unlock()
	lastAppliedRules.Put(netNS, data)
}

var (
	lastAppliedRules   dict.HDict[string, *AppliedRules]
	lastAppliedRulesMx sync.RWMutex

	_ Patch = (*UpdateFqdnNetsets)(nil)
)

func (UpdateFqdnNetsets) isAppliedRulesPatch() {}

// String impl Stringer interface
func (p UpdateFqdnNetsets) String() string {
	return fmt.Sprintf("fqdn-netset(ip-v: %v; domain: '%s'; addrs: %s)",
		p.IPVersion, p.FQDN, slice2stringer(p.Addresses...))
}

// NetSet -
func (ns UpdateFqdnNetsets) NetSet() []net.IPNet {
	isV6 := ns.IPVersion == iplib.IP6Version
	bits := tern(isV6, net.IPv6len, net.IPv4len) * 8
	mask := net.CIDRMask(bits, bits)
	ret := make([]net.IPNet, len(ns.Addresses))
	for i, ip := range ns.Addresses {
		ret[i] = net.IPNet{IP: ip, Mask: mask}
	}
	return ret
}

// Appply -
func (ns UpdateFqdnNetsets) Appply(ctx context.Context, rules *AppliedRules) error {
	if !isIn(ns.IPVersion, sli(iplib.IP4Version, iplib.IP6Version)) {
		return ErrPatchNotApplicable
	}
	tx, err := NewTx(rules.NetNS)
	if err != nil {
		return err
	}
	defer tx.Close()
	var nftConf NFTablesConf
	if err = nftConf.Load(tx.Conn); err != nil {
		return err
	}
	targetTable := NfTableKey{
		TableFamily: nftlib.TableFamilyINet,
		Name:        rules.TargetTable,
	}
	netSets := nftConf.Sets.At(targetTable)
	netsetName := nameUtils{}.
		nameOfFqdnNetSet(ns.IPVersion, ns.FQDN)
	set := netSets.At(netsetName)
	if set.Set == nil {
		return ErrPatchNotApplicable
	}
	elements := setsUtils{}.nets2SetElements(ns.NetSet(), ns.IPVersion)
	if err = tx.SetAddElements(set.Set, elements); err != nil {
		panic(err)
	}
	if err = tx.FlushAndClose(); err != nil {
		return err
	}
	data := rules.LocalData.SG2FQDNRules.Resolved
	src := tern(ns.IPVersion == iplib.IP4Version,
		&data.A, &data.AAAA)
	data.Lock()
	defer data.Unlock()
	src.Put(ns.FQDN, internal.DomainAddresses{
		TTL: ns.TTL,
		IPs: ns.Addresses,
	})
	return nil
}

//DNS resolver

func (WithNetNS) isNfTablesProcessorOpt() {}
func (BaseRules) isNfTablesProcessorOpt() {}

// Patch -
func (rules *AppliedRules) Patch(p Patch, apply func() error) error {
	switch v := p.(type) {
	case UpdateFqdnNetsets:
		if !isIn(v.IPVersion, sli(iplib.IP4Version, iplib.IP6Version)) {
			return ErrPatchNotApplicable
		}
		data := rules.LocalData.SG2FQDNRules.Resolved
		src := tern(v.IPVersion == iplib.IP4Version,
			&data.A, &data.AAAA)
		if _, ok := src.Get(v.FQDN); !ok {
			break
		}
		data.Lock()
		defer data.Unlock()
		src.Put(v.FQDN, internal.DomainAddresses{
			TTL: v.TTL,
			IPs: v.Addresses,
		})
		if err := apply(); err != nil {
			return err
		}
		return nil
	}
	return ErrPatchNotApplicable
}
