package internal

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	utils "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/protos/pkg/api/common"
	sgroupsAPI "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

const (
	// RcRules -
	RcRules = SGroupsProvider + "_rules"
	// RcLabelSgFrom -
	RcLabelSgFrom = "sg_from"
	// RcLabelSgTo -
	RcLabelSgTo = "sg_to"
	// RcLabelProto -
	RcLabelProto = "proto"
	// RcLabelPortsFrom -
	RcLabelPortsFrom = "ports_from"
	// RcLabelPortsTo -
	RcLabelPortsTo = "ports_to"
)

/*// respurce skeleton
items:
- proto: TCP
  sg_from: sg1
  sg_to: sg2
  ports_from: 200-300 500-600 22 24
  ports_to: 200-300 500-600 22 24
- proto: UDP
  sg_from: sg1
  sg_to: sg2
  ports_from: 200-300 500-600 22 24
  ports_to: 200-300 500-600 22 24
*/

// SGroupsRcRules sg-rules resource
func SGroupsRcRules() *schema.Resource {
	return &schema.Resource{
		Description:   fmt.Sprintf("represents SG rules resource in '%s' provider", SGroupsProvider),
		CreateContext: rulesC,
		UpdateContext: rulesU,
		DeleteContext: rulesD,
		ReadContext:   rulesR,
		Schema: map[string]*schema.Schema{
			RcLabelItems: {
				Optional:    true,
				Description: "SG rules list",
				Type:        schema.TypeList,
				Elem: &schema.Resource{
					Description: "SG rule element",
					Schema: map[string]*schema.Schema{
						RcLabelProto: {
							Description: "ip-proto tcp|udp",
							Type:        schema.TypeString,
							Required:    true,
							ValidateDiagFunc: func(i interface{}, p cty.Path) diag.Diagnostics {
								s := i.(string)
								ok := strings.EqualFold(common.Networks_NetIP_TCP.String(), s) ||
									strings.EqualFold(common.Networks_NetIP_UDP.String(), s)
								if ok {
									return nil
								}
								return diag.Diagnostics{{
									Severity:      diag.Error,
									AttributePath: p,
									Summary:       fmt.Sprintf("bad proto: '%s'", s),
								}}
							},
						},
						RcLabelSgFrom: {
							Description: "SG from",
							Type:        schema.TypeString,
							Required:    true,
						},
						RcLabelSgTo: {
							Description: "SG to",
							Type:        schema.TypeString,
							Required:    true,
						},
						RcLabelPortsFrom: {
							Description:      "port ranges from",
							Type:             schema.TypeString,
							ValidateDiagFunc: validatePortRanges,
							Optional:         true,
							DiffSuppressFunc: portRangesNoDiff,
						},
						RcLabelPortsTo: {
							Description:      "port ranges to",
							Type:             schema.TypeString,
							ValidateDiagFunc: validatePortRanges,
							Optional:         true,
							DiffSuppressFunc: portRangesNoDiff,
						},
					},
				},
			},
		},
	}
}

type crudRules = listedRcCRUD[sgroupsAPI.Rule]

func rulesR(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	items, _ := rd.Get(RcLabelItems).([]any)
	var h listedResource[sgroupsAPI.Rule]
	h.init("", ";")
	if err := h.addlist(items, tf2protoRule); err != nil {
		return diag.FromErr(err)
	}
	if len(h.mapped) == 0 {
		rd.SetId(noneID)
		return nil
	}
	var req sgroupsAPI.FindRulesReq
	h.walk(func(k string, r *sgroupsAPI.Rule) bool {
		req.SgFrom = append(req.SgFrom, r.GetSgFrom().GetName())
		req.SgTo = append(req.SgTo, r.GetSgTo().GetName())
		return true
	})
	resp, err := i.(SGClient).FindRules(ctx, &req)
	if err != nil {
		return diag.FromErr(err)
	}
	var h1 listedResource[model.SGRule]
	h1.init(strings.Join(h.source, h.sep), h.sep)
	for _, rule := range resp.GetRules() {
		var mr model.SGRule
		if mr, err = utils.Proto2ModelSGRule(rule); err != nil {
			return diag.FromErr(err)
		}
		if id := mr.String(); h.mapped[id] != nil {
			_ = h1.set(id, &mr)
		}
	}
	items = items[:0]
	h1.walk(func(_ string, mr *model.SGRule) bool {
		if mr != nil {
			items = append(items, modelRule2tf(mr))
		}
		return true
	})
	rd.SetId(h1.id(noneID))
	return diag.FromErr(
		rd.Set(RcLabelItems, items),
	)
}

func rulesU(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudRules{tf2proto: tf2protoRule, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.update(ctx, rd))
}

func rulesC(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudRules{tf2proto: tf2protoRule, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.create(ctx, rd))
}

func rulesD(ctx context.Context, rd *schema.ResourceData, i interface{}) diag.Diagnostics {
	crud := crudRules{tf2proto: tf2protoRule, labelItems: RcLabelItems, client: i.(SGClient)}
	return diag.FromErr(crud.delete(ctx, rd))
}

func validatePortRanges(i interface{}, p cty.Path) diag.Diagnostics {
	src := i.(string)
	if arePortRangesValid(src) {
		return nil
	}
	return diag.Diagnostics{{
		Severity:      diag.Error,
		Summary:       fmt.Sprintf("bad port ranges: '%s'", src),
		AttributePath: p,
	}}
}

func arePortRangesValid(src string) bool {
	src = strings.TrimSpace(src)
	for len(src) > 0 {
		m := parsePortsRE.FindStringSubmatch(src)
		if len(m) < 4 {
			return false
		}
		src = src[len(m[0]):]
		if len(m[1]) == 0 {
			return false
		}
		if a, b := len(m[2]), len(m[3]); !(a|b == 0 || a*b != 0) {
			return false
		}
	}
	return true
}

func parsePorts(src string, f func(start, end uint16) error) error {
	var (
		l, r uint64
		err  error
	)
	src = strings.TrimSpace(src)
	for len(src) > 0 {
		m := parsePortsRE.FindStringSubmatch(src)
		if len(m) < 4 {
			return errIncorrectPortsSource
		}
		src = src[len(m[0]):]
		if a, b := len(m[2]), len(m[3]); a*b != 0 {
			l, err = strconv.ParseUint(m[2], 10, 16)
			if err == nil {
				r, err = strconv.ParseUint(m[3], 10, 16)
			}
		} else {
			l, err = strconv.ParseUint(m[1], 10, 16)
			r = l
		}
		if err == nil {
			if uint16(r) < uint16(l) {
				return errIncorrectPortsSource
			}
			err = f(uint16(l), uint16(r))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func foldPorts(ranges model.PortRanges) string {
	buf := bytes.NewBuffer(nil)
	ranges.Iterate(func(rng model.PortRange) bool {
		if !rng.IsNull() {
			if buf.Len() > 0 {
				_ = buf.WriteByte(' ')
			}
			l, r := rng.Bounds()
			r = r.AsIncluded()
			v, _ := l.GetValue()
			_, _ = fmt.Fprintf(buf, "%v", v)
			if r.Cmp(l) != 0 {
				v, _ := r.GetValue()
				_, _ = fmt.Fprintf(buf, "-%v", v)
			}
		}
		return true
	})
	return buf.String()
}

func modelRule2tf(mr *model.SGRule) map[string]any {
	return map[string]any{
		RcLabelSgFrom:    mr.SgFrom.Name,
		RcLabelSgTo:      mr.SgTo.Name,
		RcLabelProto:     mr.Transport.String(),
		RcLabelPortsFrom: foldPorts(mr.PortsFrom),
		RcLabelPortsTo:   foldPorts(mr.PortsTo),
	}
}

func tf2protoRule(raw any) (string, *sgroupsAPI.Rule, error) {
	item := raw.(map[string]any)
	proto, ok := common.Networks_NetIP_Transport_value[strings.ToUpper(item[RcLabelProto].(string))]
	if !ok {
		return "", nil, errors.Errorf("bad proto '%s'", item[RcLabelProto].(string))
	}
	rule := &sgroupsAPI.Rule{
		Transport: common.Networks_NetIP_Transport(proto),
		SgFrom: &sgroupsAPI.SecGroup{
			Name: item[RcLabelSgFrom].(string),
		},
		SgTo: &sgroupsAPI.SecGroup{
			Name: item[RcLabelSgTo].(string),
		},
	}
	id, err := utils.Proto2ModelSGRuleIdentity(rule)
	if err != nil {
		return "", nil, err
	}
	if portsFrom, ok := item[RcLabelPortsFrom].(string); ok {
		err := parsePorts(portsFrom, func(start, end uint16) error {
			rule.PortsFrom = append(rule.PortsFrom, &common.Networks_NetIP_PortRange{
				From: uint32(start),
				To:   uint32(end),
			})
			return nil
		})
		if err != nil {
			return "", nil, errors.Errorf("ports-from '%s', %s", portsFrom, err.Error())
		}
	}
	if portsTo, ok := item[RcLabelPortsTo].(string); ok {
		err := parsePorts(portsTo, func(start, end uint16) error {
			rule.PortsTo = append(rule.PortsTo, &common.Networks_NetIP_PortRange{
				From: uint32(start),
				To:   uint32(end),
			})
			return nil
		})
		if err != nil {
			return "", nil, errors.Errorf("ports-to '%s', %s", portsTo, err.Error())
		}
	}
	return id.String(), rule, nil
}

var (
	errIncorrectPortsSource = fmt.Errorf("incorrect port range(s) source")
	parsePortsRE            = regexp.MustCompile(`^\s*((?:(\d+)\s*-\s*(\d+))|\d+)\s*`)
)
