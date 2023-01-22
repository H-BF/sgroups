package cases

import (
	"context"
	"sort"
	"strings"

	"github.com/H-BF/corlib/pkg/slice"
	sgAPI "github.com/H-BF/protos/pkg/api/sgroups"
	conv "github.com/H-BF/sgroups/internal/api/sgroups"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/pkg/errors"
)

type (
	//SgToSgsIndex ...
	SgToSgsIndex struct {
		SgFrom    SgName
		Transport model.NetworkTransport
	}

	//SgToSgsItem ...
	SgToSgsItem struct {
		SgTo      SgName
		PortsFrom model.PortRanges
		PortsTo   model.PortRanges
	}

	//SgToSgs SG to SG(s) aggregate by SG name and Ttransport
	SgToSgs map[SgToSgsIndex]*[]SgToSgsItem
)

// Load it loads state from SG service
func (agg *SgToSgs) Load(ctx context.Context, client SGClient, from, to []SgName) error {
	const api = "SgToSgs/Load"

	if (*agg) == nil {
		*agg = make(SgToSgs)
	}
	req := &sgAPI.FindRulesReq{
		SgFrom: from,
		SgTo:   to,
	}
	resp, err := client.FindRules(ctx, req)
	if err != nil {
		return errors.WithMessage(err, api)
	}
	for _, srcRule := range resp.GetRules() {
		var rule model.SGRule
		if rule, err = conv.Proto2ModelSGRule(srcRule); err != nil {
			return errors.WithMessage(err, api)
		}
		ndx := SgToSgsIndex{SgFrom: rule.SgFrom.Name, Transport: rule.Transport}
		itm := SgToSgsItem{
			SgTo:      rule.SgTo.Name,
			PortsFrom: rule.PortsFrom,
			PortsTo:   rule.PortsTo,
		}
		items := (*agg)[ndx]
		if items == nil {
			items = new([]SgToSgsItem)
			(*agg)[ndx] = items
		}
		*items = append(*items, itm)
	}
	return nil
}

// Dedup it deduplicates internal lists
func (agg *SgToSgs) Dedup() {
	for _, items := range *agg {
		sort.Slice(*items, func(i, j int) bool {
			l, r := (*items)[i], (*items)[j]
			return !strings.EqualFold(l.SgTo, r.SgTo) &&
				strings.Compare(l.SgTo, r.SgTo) < 0
		})
		_ = slice.DedupSlice(items, func(i, j int) bool {
			l, r := (*items)[i], (*items)[j]
			return strings.EqualFold(l.SgTo, r.SgTo)
		})
	}
}

// SgNameSet it gets SG name set used in this aggregate
func (agg SgToSgs) SgNameSet() map[SgName]struct{} {
	ret := make(map[SgName]struct{}, len(agg))
	for k, items := range agg {
		ret[k.SgFrom] = struct{}{}
		for _, it := range *items {
			ret[it.SgTo] = struct{}{}
		}
	}
	return ret
}
