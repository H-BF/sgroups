package main

import (
	"context"
	"flag"
	"os"

	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	address = "registry.terraform.io/h-bf/sgroups"
	version = "dev"
)

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: address,
		Debug:   debug,
	}
	ctx := context.Background()
	if err := providerserver.Serve(ctx, provider.Factory(version), opts); err != nil {
		tflog.Error(ctx, err.Error())
		os.Exit(1)
	}
}
