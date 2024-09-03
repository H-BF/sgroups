package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	sgAPI "github.com/H-BF/sgroups/v2/internal/api/sgroups"
	"github.com/H-BF/sgroups/v2/internal/app/sgroups-tf-provider/validators"
	client "github.com/H-BF/sgroups/v2/internal/grpc"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"google.golang.org/grpc/credentials"
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

type (
	sgroupsProvider struct {
		version string
	}

	providerConfig struct {
		Address          types.String `tfsdk:"address"`
		UseAPIPathPrefix types.String `tfsdk:"api_path_prefix"`
		DialDuration     types.String `tfsdk:"dial_duration"`
		UseJsonCodec     types.Bool   `tfsdk:"use_json_codec"`
		Autn             types.Object `tfsdk:"authn"`
	}

	tlsAuthnCongig struct {
		Cert         types.Object `tfsdk:"cert"`
		ServerVerify types.Object `tfsdk:"server_verify"`
	}

	tlsAuthnServerVerify struct {
		ServerName  types.String `tfsdk:"server_name"`
		RootCaFiles types.Set    `tfsdk:"root_ca_files"`
	}

	tlsAuthnCert struct {
		KeyFile  types.String `tfsdk:"key_file"`
		CertFile types.String `tfsdk:"cert_file"`
	}
)

/*//              --== SGROUPS provider config SCHEMA  ==--
provider "sgroups" {
   address = "address" #required ~ like "tcp://<ip|domain>:port"
   dial_duration = "15s" #optional
   use_json_codec = <true|false> #optional
   authn = { #optional
      tls = { #required
         cert = { #optional
            key_file = "key-file.pem"  #required ~ like "./../../../../bin/tls/server-key.pem"
            cert_file = "cert-file.pem" #required ~ like "./../../../../bin/tls/server-cert.pem"
         }
         server_verify = { #optional
            server_name = "server-name" #optional ~ like "srv1"
            root_ca_files = ["file1.pem", "file2.pem", ...]  #required ~ like ["./../../../../bin/tls/ca-cert.pem"]
         }
      }
   }
}
*/

// Metadata impl provider.Provider
func (s *sgroupsProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sgroups"
	resp.Version = s.version
}

// Schema impl provider.Provider
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
			"api_path_prefix": schema.StringAttribute{
				Optional:    true,
				Description: "'SGROUPS' service API path prefix",
				Validators: []validator.String{
					validators.IsPath(),
				},
			},
			"authn": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "type of authentication",
				Attributes: map[string]schema.Attribute{
					"tls": s.tlsAuthnSchema(),
				},
			},
		},
	}
}

// Configure impl provider.Provider
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
	if s := config.UseAPIPathPrefix.ValueString(); len(s) > 0 {
		clientBuilder = clientBuilder.WithPathPrefix(s)
	}
	if authn := config.Autn; !(authn.IsNull() || authn.IsUnknown()) {
		var raw struct {
			TLS types.Object `tfsdk:"tls"`
		}
		var tlsConf tlsAuthnCongig
		var creds credentials.TransportCredentials
		di := authn.As(ctx, &raw, basetypes.ObjectAsOptions{})
		if di.HasError() {
			resp.Diagnostics.Append(di...)
			return
		}
		if !(raw.TLS.IsNull() || raw.TLS.IsUnknown()) {
			di = raw.TLS.As(ctx, &tlsConf, basetypes.ObjectAsOptions{})
			if !di.HasError() {
				creds, di = tlsConf.creds(ctx)
			}
		}
		if di.HasError() {
			resp.Diagnostics.Append(di...)
			return
		}
		clientBuilder = clientBuilder.WithCreds(creds)
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

// DataSources impl provider.Provider
func (s *sgroupsProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// Resources impl provider.Provider
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

func (s *sgroupsProvider) tlsAuthnSchema() schema.Attribute {
	return schema.SingleNestedAttribute{
		Required:    true,
		Description: "TLS type authentication",
		Attributes: map[string]schema.Attribute{
			"cert": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "client certificate and private key",
				Attributes: map[string]schema.Attribute{
					"key_file": schema.StringAttribute{
						Required:    true,
						Description: "private key filename",
						Validators: []validator.String{
							stringvalidator.LengthAtLeast(1),
						},
					},
					"cert_file": schema.StringAttribute{
						Required:    true,
						Description: "cert filename",
						Validators: []validator.String{
							stringvalidator.LengthAtLeast(1),
						},
					},
				},
			},
			"server_verify": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "the client client will verify server",
				Attributes: map[string]schema.Attribute{
					"server_name": schema.StringAttribute{
						Optional:    true,
						Description: "the client will verify only this server name",
					},
					"root_ca_files": schema.SetAttribute{
						Required:    true,
						ElementType: types.StringType,
						Description: "root CA files to verify server",
						Validators: []validator.Set{
							setvalidator.SizeAtLeast(1),
						},
					},
				},
			},
		},
	}
}

func (tlsc tlsAuthnCongig) creds(ctx context.Context) (creds credentials.TransportCredentials, diags diag.Diagnostics) {
	tlsConf := tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
	}
	var di diag.Diagnostics
	if crt := tlsc.Cert; !(crt.IsNull() || crt.IsUnknown()) {
		var c tlsAuthnCert
		if di = crt.As(ctx, &c, basetypes.ObjectAsOptions{}); !di.HasError() {
			di = c.fillTLSconf(ctx, &tlsConf)
		}
	}
	if ver := tlsc.ServerVerify; !(di.HasError() || ver.IsNull() || ver.IsUnknown()) {
		var verSrv tlsAuthnServerVerify
		if di = ver.As(ctx, &verSrv, basetypes.ObjectAsOptions{}); !di.HasError() {
			di = verSrv.fillTLSconf(ctx, &tlsConf)
		}
	}
	if di.HasError() {
		diags.Append(di...)
		return nil, diags
	}
	return credentials.NewTLS(&tlsConf), nil
}

func (v tlsAuthnServerVerify) fillTLSconf(ctx context.Context, cnf *tls.Config) (diags diag.Diagnostics) {
	cnf.InsecureSkipVerify = false
	cnf.ServerName = v.ServerName.ValueString()
	var attrs []types.String
	di := v.RootCaFiles.ElementsAs(ctx, &attrs, false)
	if di.HasError() {
		diags.Append(di...)
		return diags
	}
	pool := x509.NewCertPool()
	for _, a := range attrs {
		f := a.ValueString()
		pem, err := os.ReadFile(f)
		if err != nil {
			diags.AddError(
				err.Error(),
				fmt.Sprintf("on reading CA file '%s'", f),
			)
			return diags
		}
		if !pool.AppendCertsFromPEM(pem) {
			diags.AddError(
				fmt.Sprintf("unable adopt CA file '%s' onto CA pool", f),
				"",
			)
			return diags
		}
	}
	cnf.RootCAs = pool
	return nil
}

func (v tlsAuthnCert) fillTLSconf(_ context.Context, cnf *tls.Config) (diags diag.Diagnostics) {
	keyFile := v.KeyFile.ValueString()
	certFile := v.CertFile.ValueString()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		diags.AddError(err.Error(), "on make cert/key pair")
		return diags
	}
	cnf.Certificates = []tls.Certificate{cert}
	return nil
}
