package provider

import (
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
)

var (
	actionValidator = stringvalidator.OneOf(
		protos.RuleAction_DROP.String(),
		protos.RuleAction_ACCEPT.String())
)
