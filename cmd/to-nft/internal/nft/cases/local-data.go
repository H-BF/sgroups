package cases

import (
	"context"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/host"

	"github.com/H-BF/corlib/logger"
	"github.com/pkg/errors"
)

// LocalData are used by agent to build local firewall rules
type LocalData struct {
	LocalSGs      SGs
	SG2SGRules    SG2SGRules
	SG2FQDNRules  SG2FQDNRules
	SgIcmpRules   SgIcmpRules
	SgSgIcmpRules SgSgIcmpRules
	CidrSgRules   CidrSgRules
	Networks      SGsNetworks
}

// LocalDataLoader
type LocalDataLoader struct {
	Logger logger.TypeOfLogger
	DnsRes internal.DomainAddressQuerier // optional
}

// IsEq checks wether this object is equal the other one
func (ld *LocalData) IsEq(other LocalData) bool {
	return ld.LocalSGs.IsEq(other.LocalSGs) &&
		ld.SG2SGRules.IsEq(other.SG2SGRules) &&
		ld.SG2FQDNRules.IsEq(other.SG2FQDNRules) &&
		ld.SgIcmpRules.IsEq(other.SgIcmpRules) &&
		ld.SgSgIcmpRules.IsEq(other.SgSgIcmpRules) &&
		ld.CidrSgRules.IsEq(other.CidrSgRules) &&
		ld.Networks.IsEq(other.Networks)
}

// Load -
func (loader LocalDataLoader) Load(ctx context.Context, client SGClient, ncnf host.NetConf) (res LocalData, err error) {
	defer func() {
		err = errors.WithMessage(err, "LocalData/Load")
	}()

	return res, err
}

/*//
func stringers(args ...fmt.Stringer) []fmt.Stringer {
	return args
}
*/
