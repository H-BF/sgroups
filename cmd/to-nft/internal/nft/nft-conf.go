//go:build linux
// +build linux

package nft

import (
	nftrc "github.com/H-BF/corlib/pkg/nftables"
	nftlib "github.com/google/nftables"
)

// type aliases
type (
	// NfTableKey is a type alias
	NfTableKey = nftrc.NfTableKey
	// NfChainKey is a type alias
	NfChainKey = nftrc.NfChainKey
	// NfChain is a type alias
	NfChain = nftrc.NfChain
	// NfSet is a type alias
	NfSet = nftrc.NfSet
	// NFTablesConf is a type alias
	NFTablesConf = nftrc.StateOfNFTables
)

// NFTconfLoad it loads current nftables config
func NFTconfLoad(conn *nftlib.Conn) (NFTablesConf, error) {
	lister := nftrc.ListerFromConn(conn)
	return nftrc.LoadState(lister)
}
