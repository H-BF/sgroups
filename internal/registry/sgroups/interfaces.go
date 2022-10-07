package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
)

type (
	//Writer db writer abstract
	Writer interface {
		SyncNetworks(ctx context.Context, networks []model.Network, scope Scope, opts ...Option) error
		SyncSecurityGroups(ctx context.Context, sgs []model.SecurityGroup, scope Scope, opts ...Option) error
		SyncSGRules(ctx context.Context, rules []model.SGRule, scope Scope, opts ...Option) error
	}

	//Reader db reader abstract
	Reader interface {
		ListNetworks(ctx context.Context, consume func(model.Network) error, scope Scope) error
		ListSecurityGroups(ctx context.Context, consume func(model.SecurityGroup) error, scope Scope) error
		ListSGRules(ctx context.Context, consume func(model.SGRule) error, scope Scope) error
	}
)
