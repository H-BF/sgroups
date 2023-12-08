package sgroups

import (
	"context"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/internal/patterns"

	"github.com/pkg/errors"
)

type (
	readerNoClose interface {
		ListNetworks(ctx context.Context, consume func(model.Network) error, scope Scope) error
		ListSecurityGroups(ctx context.Context, consume func(model.SecurityGroup) error, scope Scope) error
		ListSGRules(ctx context.Context, consume func(model.SGRule) error, scope Scope) error
		ListFqdnRules(ctx context.Context, consume func(model.FQDNRule) error, scope Scope) error
		ListSgIcmpRules(ctx context.Context, consume func(model.SgIcmpRule) error, scope Scope) error
		ListSgSgIcmpRules(ctx context.Context, consume func(model.SgSgIcmpRule) error, scope Scope) error
		ListCidrSgRules(ctx context.Context, consume func(model.CidrSgRule) error, scope Scope) error
		GetSyncStatus(ctx context.Context) (*model.SyncStatus, error)
	}

	//Reader db reader abstract
	Reader interface {
		readerNoClose
		Close() error
	}

	//Writer db writer abstract
	Writer interface {
		SyncNetworks(ctx context.Context, networks []model.Network, scope Scope, opts ...Option) error
		SyncSecurityGroups(ctx context.Context, sgs []model.SecurityGroup, scope Scope, opts ...Option) error
		SyncSGRules(ctx context.Context, rules []model.SGRule, scope Scope, opts ...Option) error
		SyncFqdnRules(ctx context.Context, rules []model.FQDNRule, scope Scope, opts ...Option) error
		SyncSgIcmpRules(ctx context.Context, rules []model.SgIcmpRule, scope Scope, opts ...Option) error
		SyncSgSgIcmpRules(ctx context.Context, rules []model.SgSgIcmpRule, scope Scope, opts ...Option) error
		SyncCidrSgRules(ctx context.Context, rules []model.CidrSgRule, scope Scope, opts ...Option) error
		Commit() error
		Abort()
	}

	//Registry abstract db registry
	Registry interface {
		Subject() patterns.Subject
		Writer(ctx context.Context) (Writer, error)
		Reader(ctx context.Context) (Reader, error)
		Close() error
	}
)

// ErrValidate validation failure
var ErrValidate = errors.New("validation failure")
