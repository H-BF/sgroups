package main

import (
	"context"
	"flag"
	"os"

	provider "github.com/H-BF/sgroups/v2/internal/app/sgroups-tf-provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	// Address - address of TF provider in registry
	Address = "registry.terraform.io/h-bf/sgroups"
	// Version - the version of provider
	Version = "v2"
)

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: Address,
		Debug:   debug,
	}
	ctx := context.Background()
	if err := providerserver.Serve(ctx, provider.Factory(Version), opts); err != nil {
		tflog.Error(ctx, err.Error())
		os.Exit(1)
	}
}
