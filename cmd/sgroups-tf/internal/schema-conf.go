package internal

import (
	"context"
	"fmt"
	"time"

	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	grpcc "github.com/H-BF/sgroups/internal/grpc"

	pkgNet "github.com/H-BF/corlib/pkg/net"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// SGClient is an alias to 'sgroups' API Client
type SGClient = sgAPI.Client

// SGroupsProvider ...
const SGroupsProvider = "sgroups"

const (
	// CnfSgroupsAddress ...
	CnfSgroupsAddress = SGroupsProvider + "_address"

	// CnfSgroupsDialDuration ...
	CnfSgroupsDialDuration = SGroupsProvider + "_dial_duration"
)

// SGroupsConfigSchema ...
func SGroupsConfigSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		CnfSgroupsAddress: {
			Description: "'SGROUPS' service address",
			Type:        schema.TypeString,
			Required:    true,
			DefaultFunc: schema.EnvDefaultFunc("SGROUPS_ADDRESS", "tcp://127.0.0.1:9000"),
			ValidateDiagFunc: func(v interface{}, p cty.Path) diag.Diagnostics {
				s := v.(string)
				_, err := pkgNet.ParseEndpoint(s)
				if err == nil {
					return nil
				}
				return diag.Diagnostics{{
					Severity:      diag.Error,
					AttributePath: p,
					Detail:        fmt.Sprintf("bad value '%s'", s),
					Summary:       err.Error(),
				}}
			},
		},
		CnfSgroupsDialDuration: {
			Description: "'SGROUPS' service dial max duration",
			Type:        schema.TypeString,
			Optional:    true,
			DefaultFunc: schema.EnvDefaultFunc("SGROUPS_DIAL_DURATION", "10s"),
			ValidateDiagFunc: func(v interface{}, p cty.Path) diag.Diagnostics {
				s := v.(string)
				_, err := time.ParseDuration(s)
				if err == nil {
					return nil
				}
				return diag.Diagnostics{{
					Severity:      diag.Error,
					AttributePath: p,
					Detail:        fmt.Sprintf("bad value '%s'", s),
					Summary:       err.Error(),
				}}
			},
		},
	}
}

// SGroupsConfigure do configure 'sgrpups' provider
func SGroupsConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var connDuration time.Duration
	addr := d.Get(CnfSgroupsAddress).(string)
	if v, ok := d.GetOk(CnfSgroupsDialDuration); ok {
		d, e := time.ParseDuration(v.(string))
		if e != nil {
			return nil, diag.Diagnostics{{
				Severity: diag.Error,
				Summary:  e.Error(),
				Detail:   fmt.Sprintf("bad param '%s': %s", CnfSgroupsDialDuration, v.(string)),
			}}
		}
		connDuration = d
	}
	c, err := grpcc.ClientFromAddress(addr).
		WithDialDuration(connDuration).
		New(ctx)
	if err != nil {
		return nil, diag.FromErr(err)
	}
	return sgAPI.NewClient(c), nil
}
