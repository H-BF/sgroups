//go:build linux
// +build linux

package conf

import (
	"context"
	nftlib "github.com/google/nftables"
)

// Lister -
type Lister interface {
	ListTables() ([]*nftlib.Table, error)
	ListChains() ([]*nftlib.Chain, error)
	GetSets(*nftlib.Table) ([]*nftlib.Set, error)
	GetObjects(*nftlib.Table) ([]nftlib.Obj, error)
	GetSetElements(*nftlib.Set) ([]nftlib.SetElement, error)
	GetRules(*nftlib.Chain) ([]*nftlib.Rule, error)
}

// ListerFromConn -
func ListerFromConn(c *nftlib.Conn) listerFromConn {
	return listerFromConn{Conn: c}
}

type listerFromConn struct {
	*nftlib.Conn
}

var _ Lister = (*listerFromConn)(nil)

func (lst listerFromConn) GetRules(chn *nftlib.Chain) ([]*nftlib.Rule, error) {
	return lst.Conn.GetRules(chn.Table, chn)
}

func (lst listerFromConn) Fetch(_ context.Context) (StateOfNFTables, error) {
	return LoadState(lst)
}
