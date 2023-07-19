package main

import (
	"context"
	"strings"

	"github.com/H-BF/sgroups/internal/app"
	appdb "github.com/H-BF/sgroups/internal/registry/sgroups"
	"github.com/H-BF/sgroups/pkg/atomic"

	"github.com/pkg/errors"
)

type (
	registryConstrutor func(context.Context) (appdb.Registry, error)
)

func getAppRegistry() appdb.Registry {
	var ret appdb.Registry
	if !storedAppRegistry.Fetch(func(v appdb.Registry) { ret = v }) {
		panic(errors.New("need setup db registry"))
	}
	return ret
}

var (
	storedAppRegistry atomic.Value[appdb.Registry]

	registryConstructors = map[string]registryConstrutor{
		"internal": newInternalDB,
		"postgres": newPostgresDB,
	}
)

func setupRegistry() error {
	ctx := app.Context()
	st, err := StorageType.Value(ctx)
	if err != nil {
		return err
	}
	f, ok := registryConstructors[strings.ToLower(strings.TrimSpace(st))]
	if !ok {
		return errors.Errorf("unknown registry storage type '%s'", st)
	}
	var db appdb.Registry
	if db, err = f(ctx); err != nil {
		return err
	}
	storedAppRegistry.Store(db, func(old appdb.Registry) {
		_ = old.Close()
	})
	return nil
}

var _ = setupRegistry
