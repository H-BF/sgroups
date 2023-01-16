package nft

import (
	"math"

	"github.com/pkg/errors"
)

var (
	//ErrNfTablesProcessor points to error came from 'NfTablesProcessor'
	ErrNfTablesProcessor = errors.New("NfTablesProcessor")

	//ErrPortRange is a port range error
	ErrPortRange = errors.Errorf("out of port range [0, %v)", 0, math.MaxUint16)
)
