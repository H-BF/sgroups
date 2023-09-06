package nft

import (
	"math"

	"github.com/pkg/errors"
)

var (
	//ErrNfTablesProcessor points to error came from 'NfTablesProcessor'
	ErrNfTablesProcessor = errors.New("NfTablesProcessor error")

	//ErrPortRange is a port range error
	ErrPortRange = errors.Errorf("out of port range [0, %v)", math.MaxUint16)
)
