package main

import (
	details "github.com/H-BF/sgroups/cmd/tf-provider/internal"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return &schema.Provider{
				Schema:               details.SGroupsConfigSchema(),
				ConfigureContextFunc: details.SGroupsConfigure,
				ResourcesMap: map[string]*schema.Resource{
					details.RcLabelNetworks: details.SGroupsRcNetworks(),
					details.RcLabelSGs:      details.SGroupsRcSGs(),
					details.RcLabelRules:    details.SGroupsRcRules(),
				},
			}
		},
	})
}
