package nft

import (
	"github.com/pkg/errors"
)

var (
	// ErrNfTablesProcessor points to error came from 'NfTablesProcessor'
	ErrNfTablesProcessor = errors.New("NfTablesProcessor error")

	// ErrPatchNotApplicable
	ErrPatchNotApplicable = errors.New("patch is not applicable")
)
