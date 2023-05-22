package app

import (
	"context"
	"sync/atomic"

	"github.com/pkg/errors"
)

// Context is application context
func Context() context.Context {
	if t, ok := appCtxHolder.Load().(context.Context); ok {
		return t
	}
	panic(errors.New("seed setup app context and call 'SetContext'"))
}

// SetContext set app context
func SetContext(c context.Context) {
	appCtxHolder.Store(c)
}

var (
	appCtxHolder atomic.Value
)
