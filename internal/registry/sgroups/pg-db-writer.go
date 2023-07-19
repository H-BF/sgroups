package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
)

var _ Writer = (*pgDbWriter)(nil)

type pgDbWriter struct {
	*pgDbReader
	commit func() error
	abort  func()
}

// SyncNetworks impl Writer interface
func (wr *pgDbWriter) SyncNetworks(ctx context.Context, networks []model.Network, scope Scope, opts ...Option) error {
	return nil
}

// SyncSecurityGroups impl Writer interface
func (wr *pgDbWriter) SyncSecurityGroups(ctx context.Context, sgs []model.SecurityGroup, scope Scope, opts ...Option) error {
	return nil
}

// SyncSGRules impl Writer interface
func (wr *pgDbWriter) SyncSGRules(ctx context.Context, rules []model.SGRule, scope Scope, opts ...Option) error {
	return nil
}

// Commit impl Writer interface
func (wr *pgDbWriter) Commit() error {
	return wr.commit()
}

// Abort impl Writer interface
func (wr *pgDbWriter) Abort() {
	wr.abort()
}
