package view

import (
	"errors"
	"strconv"

	hlp "github.com/H-BF/sgroups/internal/nftables/helpers"

	dkt "github.com/H-BF/corlib/pkg/dict"
	conf "github.com/H-BF/corlib/pkg/nftables"
	"github.com/H-BF/corlib/pkg/option"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func NewRuleView(nfRule *nftables.Rule, sets dkt.HDict[string, conf.NfSet]) (*RuleView, error) {
	visitor := newViewVisitor(nfRule)
	err := visitor.visit(sets)
	return visitor.view, err
}

type viewVisitor struct {
	delegate ruleExprVisitor
	view     *RuleView
	nfRule   *nftables.Rule
}

func newViewVisitor(nfRule *nftables.Rule) viewVisitor {
	view := &RuleView{
		Chain:   nfRule.Chain.Name,
		Family:  hlp.TableFamily2S(nfRule.Table.Family),
		Table:   nfRule.Table.Name,
		Comment: "empty",
		Action:  "policy",
		Handle:  strconv.FormatUint(nfRule.Handle, 10),
	}
	return viewVisitor{initialVisitor{view}, view, nfRule}
}

func (v *viewVisitor) visit(sets dkt.HDict[string, conf.NfSet]) error {
	for _, e := range v.nfRule.Exprs {
		// TODO: extract rule comments
		switch value := e.(type) {
		case *expr.Counter:
			if _, ok := v.view.Counter.Maybe(); ok {
				return errors.New("counter already exists")
			}
			counter := Counter{
				Bytes:   float64(value.Bytes),
				Packets: float64(value.Packets),
			}
			v.view.Counter = option.MustNewOption(counter)
		case *expr.Lookup:
			if err := v.visitLookup(value, sets); err != nil {
				return err
			}
		case *expr.Cmp:
			if err := v.visitCmp(value); err != nil {
				return err
			}
		case *expr.Payload:
			if err := v.visitPayload(value); err != nil {
				return err
			}
		case *expr.Verdict:
			switch value.Kind {
			// TODO: add `masquerade` as nftables-exporter do
			case expr.VerdictDrop, expr.VerdictAccept:
				v.view.Action = hlp.VerdictKind2S(value.Kind)
			default:
			}
		case *expr.Meta:
			if err := v.visitMeta(value); err != nil {
				return err
			}
		default:
		}
	}
	return nil
}

func (v *viewVisitor) visitMeta(meta *expr.Meta) error {
	next, err := v.delegate.visitMeta(meta)
	v.delegate = next
	return err
}
func (v *viewVisitor) visitCmp(cmp *expr.Cmp) error {
	next, err := v.delegate.visitCmp(cmp)
	v.delegate = next
	return err
}
func (v *viewVisitor) visitPayload(payload *expr.Payload) error {
	next, err := v.delegate.visitPayload(payload)
	v.delegate = next
	return err
}
func (v *viewVisitor) visitLookup(lookup *expr.Lookup, setsState dkt.HDict[string, conf.NfSet]) error {
	next, err := v.delegate.visitLookup(lookup, setsState)
	v.delegate = next
	return err
}
