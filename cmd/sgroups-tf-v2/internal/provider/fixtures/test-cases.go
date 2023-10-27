package fixtures

import (
	"context"
	"testing"

	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// BackendClient -
type BackendClient = protos.SecGroupServiceClient

// AccTestCase -
type AccTestCase struct {
	TfConfig   string       `yaml:"tf-config"`
	Expected   BackendState `yaml:"expected-backend"`
	NotExpeced BackendState `yaml:"not-expected-backend"`
}

// AccTests -
type AccTests struct {
	Ctx            context.Context
	InitialBackend BackendState           `yaml:"initial-backend"`
	Cases          map[string]AccTestCase `yaml:"cases"`
}

// LoadFixture -
func (acc *AccTests) LoadFixture(t *testing.T, fixtureName string) {
	f, e := data.Open(fixtureName)
	require.NoError(t, e)
	defer f.Close() //nolint
	e = yaml.NewDecoder(f).Decode(acc)
	require.NoError(t, e)
}

// InitBackend -
func (acc *AccTests) InitBackend(t *testing.T, c BackendClient) {
	req := protos.SyncReq{
		SyncOp: protos.SyncReq_Upsert,
	}
	if nws := acc.InitialBackend.Networks; len(nws) > 0 {
		req.Subject = &protos.SyncReq_Networks{
			Networks: &protos.SyncNetworks{
				Networks: nws.Decode(),
			},
		}
		_, e := c.Sync(acc.Ctx, &req)
		require.NoError(t, e)
	}
	if sgs := acc.InitialBackend.SecGroups; len(sgs) > 0 {
		req.Subject = &protos.SyncReq_Groups{
			Groups: &protos.SyncSecurityGroups{
				Groups: sgs.Decode(),
			},
		}
		_, e := c.Sync(acc.Ctx, &req)
		require.NoError(t, e)
	}
	if rules := acc.InitialBackend.SgSgRules; len(rules) > 0 {
		req.Subject = &protos.SyncReq_SgRules{
			SgRules: &protos.SyncSGRules{
				Rules: rules.Decode(),
			},
		}
		_, e := c.Sync(acc.Ctx, &req)
		require.NoError(t, e)
	}
	if rules := acc.InitialBackend.SgFqdnRules; rules != nil {
		req.Subject = &protos.SyncReq_FqdnRules{
			FqdnRules: &protos.SyncFqdnRules{
				Rules: rules.Decode(),
			},
		}
		_, e := c.Sync(acc.Ctx, &req)
		require.NoError(t, e)
	}
}
