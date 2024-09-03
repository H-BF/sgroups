package validators

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/H-BF/sgroups/v2/internal/patterns"

	pkgNet "github.com/H-BF/corlib/pkg/net"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// IsDuration -
func IsDuration() validator.String {
	return stringValidator{
		validatorBase: validatorBase{
			description: "value must be duration",
		},
		validateFn: func(s string) error {
			_, err := time.ParseDuration(s)
			return err
		},
	}
}

// IsEndpoint -
func IsEndpoint() validator.String {
	return stringValidator{
		validatorBase: validatorBase{
			description: "value must be endpoint",
		},
		validateFn: func(s string) error {
			_, err := pkgNet.ParseEndpoint(s)
			return err
		},
	}
}

// IsPath -
func IsPath() validator.String {
	return stringValidator{
		validatorBase: validatorBase{
			description: "value must a valid PATH",
		},
		validateFn: func(s string) error {
			var p patterns.Path
			return p.Set(s)
		},
	}
}

// IsCIDR -
func IsCIDR() validator.String {
	return stringValidator{
		validatorBase: validatorBase{
			description: "value must be CIDR",
		},
		validateFn: func(s string) error {
			_, _, err := net.ParseCIDR(s)
			return err
		},
	}
}

// CheckRulePriority -
func CheckRulePriority() validator.Int64 {
	return intValidator{
		validatorBase: validatorBase{
			description: "validate RulePriority",
		},
		validateFn: func(ctx context.Context, req validator.Int64Request, resp *validator.Int64Response) {
			c := req.ConfigValue
			if c.IsNull() {
				return
			}
			if c.IsUnknown() {
				di := diag.NewAttributeErrorDiagnostic(
					req.Path,
					"the RulePriority is undefined",
					"",
				)
				resp.Diagnostics.Append(di)
			} else {
				x := c.ValueInt64()
				if !(int64(math.MinInt16) <= x && x <= int64(math.MaxInt16)) {
					di := diag.NewAttributeErrorDiagnostic(
						req.Path,
						fmt.Sprintf("the RulePriority(%v) is out of range", x),
						fmt.Sprintf("valid range interval is [%v, %v]", math.MinInt16, math.MaxInt16),
					)
					resp.Diagnostics.Append(di)
				}
			}
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
