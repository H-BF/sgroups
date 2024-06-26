package nft

import (
	nftrc "github.com/H-BF/corlib/pkg/nftables"
)

// Tx -
type Tx = nftrc.Tx

// NewTx creates transaction conn to netfilter
var NewTx = nftrc.NewTx
