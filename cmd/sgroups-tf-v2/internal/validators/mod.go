package validators

import (
	"fmt"
	"net"
	"time"

	pkgNet "github.com/H-BF/corlib/pkg/net"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

func IsDuration() validator.String {
	return parseFuncValidator{
		description: "value must be duration",
		parseFunc: func(s string) error {
			_, err := time.ParseDuration(s)
			return err
		},
	}
}

func IsEndpoint() validator.String {
	return parseFuncValidator{
		description: "value must be endpoint",
		parseFunc: func(s string) error {
			_, err := pkgNet.ParseEndpoint(s)
			return err
		},
	}
}

func IsCIDR() validator.String {
	return parseFuncValidator{
		description: "value must be CIDR",
		parseFunc: func(s string) error {
			_, _, err := net.ParseCIDR(s)
			return err
		},
	}
}

func invalidAttributeValueDiagnostic(path path.Path, description string, value string) diag.Diagnostic {
	return diag.NewAttributeErrorDiagnostic(
		path,
		"Invalid Attribute Value",
		fmt.Sprintf("Attribute %s %s, got: %s", path, description, value),
	)
}
