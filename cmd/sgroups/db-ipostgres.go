package main

import (
	"context"
	"net/url"

	appdb "github.com/H-BF/sgroups/internal/registry/sgroups"
)

func newPostgresDB(ctx context.Context) (r appdb.Registry, err error) {
	var u string
	if u, err = PostgresURL.Value(ctx); err != nil {
		return nil, err
	}
	var dbURL *url.URL
	if dbURL, err = url.Parse(u); err != nil {
		return nil, err
	}
	r, err = appdb.NewRegistryFromPG(ctx, *dbURL)
	return r, err
}
