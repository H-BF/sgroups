//go:build linux
// +build linux

package nft

import (
	inner "github.com/H-BF/sgroups/internal/nftables/conf"

	nftlib "github.com/google/nftables"
)

// type aliases
type (
	// NfTableKey is a type alias
	NfTableKey = inner.NfTableKey
	// NfChainKey is a type alias
	NfChainKey = inner.NfChainKey
	// NfChain is a type alias
	NfChain = inner.NfChain
	// NfSet is a type alias
	NfSet = inner.NfSet
	// NFTablesConf is a type alias
	NFTablesConf = inner.StateOfNFTables
)

// NFTconfLoad it loads current nftables config
func NFTconfLoad(conn *nftlib.Conn) (NFTablesConf, error) {
	lister := inner.ListerFromConn(conn)
	return inner.LoadState(lister)
}
