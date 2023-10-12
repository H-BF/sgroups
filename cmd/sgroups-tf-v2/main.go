package main

import (
	"context"
	"flag"
	"log"

	"github.com/H-BF/sgroups/cmd/sgroups-tf-v2/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var (
	address = "registry.terraform.io/h-bf/sgroups"
	version = "dev"
)

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers")
	flag.Parse()

	//address = "terraform.local/h-bf/sgroups"

	opts := providerserver.ServeOpts{
		Address: address,
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.Factory(version), opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}
