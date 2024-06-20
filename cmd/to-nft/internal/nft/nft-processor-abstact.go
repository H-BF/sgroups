package nft

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/pkg/dict"
	config "github.com/H-BF/corlib/pkg/plain-config"
	"github.com/c-robinson/iplib"
	nftlib "github.com/google/nftables"
	"github.com/pkg/errors"
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
		Apply(context.Context, *AppliedRules) error
		isAppliedRulesPatch()
	}

	// UpdateFqdnNetsets - is kind of Patch
	UpdateFqdnNetsets struct {
		IPVersion int
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
	return fmt.Sprintf("patch/fqdn-netset(IPv: %v; domain: '%s'; addrs: %s)",
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

// Apply -
func (ns UpdateFqdnNetsets) Apply(ctx context.Context, rules *AppliedRules) error {
	const api = "apply"

	if !isIn(ns.IPVersion, sli(iplib.IP4Version, iplib.IP6Version)) {
		return errors.WithMessagef(ErrPatchNotApplicable,
			"%s/%s failed cause it has bad IPv(%v)", ns, api, ns.IPVersion)
	}
	tx, err := NewTx(rules.NetNS)
	if err != nil {
		return err
	}
	defer tx.Close()
	var nftConf NFTablesConf
	if nftConf, err = NFTconfLoad(tx.Conn); err != nil {
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
		return errors.WithMessagef(ErrPatchNotApplicable,
			"%s/%s failed cause targed netset '%s' does not exist", ns, api, netsetName)
	}
	elements := setsUtils{}.nets2SetElements(ns.NetSet(), ns.IPVersion)
	if err = tx.SetAddElements(set.Set, elements); err != nil {
		panic(err)
	}
	err = tx.FlushAndClose()
	return err
}

func (WithNetNS) isNfTablesProcessorOpt() {}
func (BaseRules) isNfTablesProcessorOpt() {}
