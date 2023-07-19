package main

import (
	"context"

	appdb "github.com/H-BF/sgroups/internal/registry/sgroups"

	"github.com/pkg/errors"
)

func newInternalDB(ctx context.Context) (appdb.Registry, error) {
	m, e := appdb.NewMemDB(appdb.TblSecGroups,
		appdb.TblSecRules, appdb.TblNetworks,
		appdb.TblSyncStatus,
		appdb.IntegrityChecker4SG(),
		appdb.IntegrityChecker4Rules(),
		appdb.IntegrityChecker4Networks())
	if e != nil {
		return nil, errors.WithMessage(e, "create mem db")
	}
	return appdb.NewRegistryFromMemDB(m), nil
}
