package provider

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	sgAPI "github.com/H-BF/sgroups/internal/api/sgroups"
	g "github.com/H-BF/sgroups/internal/grpc"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/stretchr/testify/suite"
)

type (
	baseResourceTests struct {
		suite.Suite

		ctx               context.Context
		ctxCancel         func()
		servAddr          string
		sgClient          sgAPI.Client
		providerConfig    string
		providerFactories map[string]func() (tfprotov6.ProviderServer, error)
	}
)

func (sui *baseResourceTests) SetupSuite() {
	sui.ctx = context.Background()
	if dl, ok := sui.T().Deadline(); ok {
		sui.ctx, sui.ctxCancel = context.WithDeadline(sui.ctx, dl)
	}
	sui.runBackendServer()

	sui.providerConfig = `
provider "sgroups" {
	address = ` + fmt.Sprintf("%q", sui.servAddr) + `
	dial_duration = "15s"
	use_json_codec = true	
}
`
	/*// maybe test later
		authn = {
			tls = {
				cert = {
					key_file = "./../../../../bin/tls/server-key.pem"
					cert_file = "./../../../../bin/tls/server-cert.pem"
				}
				server_verify = {
					server_name = "srv1"
					root_ca_files = ["./../../../../bin/tls/ca-cert.pem"]
				}
			}
	    }
	*/
	con, err := g.ClientFromAddress(sui.servAddr).New(sui.ctx)
	sui.Require().NoError(err)
	sui.sgClient = sgAPI.NewClient(con)

	_ = os.Setenv("TF_ACC", "1")
	sui.providerFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"sgroups": providerserver.NewProtocol6WithError(Factory("test")()),
	}
}

func (sui *baseResourceTests) TearDownSuite() {
	if sui.ctxCancel != nil {
		sui.ctxCancel()
	}
}

func (sui *baseResourceTests) runBackendServer() {
	socketPath := path.Join("/tmp", fmt.Sprintf("tf-provider-test-%v-%v.socket", os.Getpid(), time.Now().Nanosecond()))
	sui.servAddr = fmt.Sprintf("unix://%s", socketPath)

	sui.Require().NoError(sgAPI.NewBackendServerAPI().Run(sui.ctx, sui.servAddr))
}

func slice2string[T fmt.Stringer](args ...T) string {
	data := bytes.NewBuffer(nil)
	for i, o := range args {
		if i > 0 {
			_, _ = data.WriteString(";  ")
		}
		_, _ = fmt.Fprintf(data, "%s", o)
	}
	return strings.ReplaceAll(data.String(), `"`, "'")
}

func TestEmpty(_ *testing.T) {}
