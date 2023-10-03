package provider

import (
	"context"
	"github.com/H-BF/sgroups/cmd/tf-provider-framework/internal/validators"
	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	client "github.com/H-BF/sgroups/internal/grpc-client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"os"
	"time"
)

func New() func() provider.Provider {
	return func() provider.Provider {
		return &sgroupsProvider{}
	}
}

var (
	_ provider.Provider = &sgroupsProvider{}
)

type sgroupsProvider struct{}

type providerConfig struct {
	Address      types.String `tfsdk:"address"`
	DialDuration types.String `tfsdk:"dial_duration"`
}

func (s *sgroupsProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sgroups"
}

func (s *sgroupsProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				Optional:    true,
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

	// Get env vars first, so if config provides them then they will be overwritten
	address := lookupEnvWithDefault("SGROUPS_ADDRESS", "tcp://127.0.0.1:9000")
	dialDuration := lookupEnvWithDefault("SGROUPS_DIAL_DURATION", "10s")

	if config.Address.ValueString() != "" {
		address = config.Address.ValueString()
	}

	if config.DialDuration.ValueString() != "" {
		dialDuration = config.DialDuration.ValueString()
	}

	connDuration, _ := time.ParseDuration(dialDuration)

	c, err := client.FromAddress(address).
		WithDialDuration(connDuration).
		New(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create Sgroups GRPC Client",
			"Sgroups GRPC Client Error: "+err.Error())
		return
	}

	client := sgAPI.NewClient(c)

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (s *sgroupsProvider) DataSources(ctx context.Context) []func() datasource.DataSource {

	return []func() datasource.DataSource{}
}

func (s *sgroupsProvider) Resources(ctx context.Context) []func() resource.Resource {

	return []func() resource.Resource{
		NewNetworkResource,
	}
}

func lookupEnvWithDefault(key, defaultValue string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		value = defaultValue
	}
	return value
}
