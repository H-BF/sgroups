package pg

import (
	"github.com/jackc/pgx/v5"
	"github.com/pkg/errors"
)

// RawRowsData -
type RawRowsData [][]any

// Len -
func (dat RawRowsData) Len() int64 {
	return int64(len(dat))
}

// ToPgxCopySource -
func (dat RawRowsData) ToPgxCopySource(offs int64) pgx.CopyFromSource {
	if offs < 0 {
		panic(errors.Errorf("offs(%v) < 0", offs))
	}
	if offs > dat.Len() {
		panic(errors.Errorf("offs(%v) > %v", offs, dat.Len()))
	}
	return pgx.CopyFromRows(dat[offs:])
}
