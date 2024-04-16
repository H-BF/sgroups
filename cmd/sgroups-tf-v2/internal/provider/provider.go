package provider

import (
	"context"
	"time"

	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/validators"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	client "github.com/H-BF/sgroups/internal/grpc"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Factory -
func Factory(version string) func() provider.Provider {
	return func() provider.Provider {
		return &sgroupsProvider{
			version: version,
		}
	}
}

var (
	_ provider.Provider = (*sgroupsProvider)(nil)
)

type sgroupsProvider struct {
	version string
}

type providerConfig struct {
	Address      types.String `tfsdk:"address"`
	DialDuration types.String `tfsdk:"dial_duration"`
	UseJsonCodec types.Bool   `tfsdk:"use_json_codec"`
}

func (s *sgroupsProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sgroups"
	resp.Version = s.version
}

func (s *sgroupsProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				Required:    true,
				Description: "'SGROUPS' service address",
				Validators: []validator.String{
					validators.IsEndpoint(),
				},
			},
			"dial_duration": schema.StringAttribute{
				Optional:    true,
				Description: "'SGROUPS' service dial max duration",
				Validators: []validator.String{
					validators.IsDuration(),
				},
			},
			"use_json_codec": schema.BoolAttribute{
				Optional:    true,
				Description: "Use GRPC-JSON codec to call 'SGROUPS' service",
			},
		},
	}
}

func (s *sgroupsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerConfig

	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	clientBuilder := client.ClientFromAddress(config.Address.ValueString())
	dialDuration := config.DialDuration.ValueString()
	if connDuration, _ := time.ParseDuration(dialDuration); connDuration > 0 {
		clientBuilder = clientBuilder.WithDialDuration(connDuration)
	}
	if config.UseJsonCodec.ValueBool() {
		clientBuilder = clientBuilder.WithDefaultCodecByName(client.JsonCodecName)
	}

	c, err := clientBuilder.New(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"create sgroups client",
			"reason: "+err.Error())
		return
	}

	sgClient := sgAPI.NewClient(c)

	resp.DataSourceData = sgClient
	resp.ResourceData = sgClient
}

func (s *sgroupsProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func (s *sgroupsProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewNetworksResource,
		NewSgsResource,
		NewFqdnRulesResource,
		NewSgToSgRulesResource,
		NewSgToSgIcmpRulesResource,
		NewCidrRulesResource,
		NewCidrSgIcmpRulesResource,
		NewIESgSgRulesResource,
		NewIESgSgIcmpRulesResource,
	}
}
