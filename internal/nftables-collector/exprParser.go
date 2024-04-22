package nftables_collector

import (
	"context"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type exprParserCtx struct {
	ctx   context.Context
	rule  *nftablesRule
	state parserState
	debug bool // enable this for development purposes to see then method not implemented on certain state
	/// ^^^^^ Иван  WTF bro?!

	setMapping  map[string]*nft.Set
	setElements map[string][]nft.SetElement

	idleState parserState
	//^^^^^^^^^^^^^ ----- что это такое?
}

func newParserCtx(ctx context.Context, rule *nftablesRule, setMapping map[string]*nft.Set, setElements map[string][]nft.SetElement) *exprParserCtx {
	// ----------------------------------------------------- ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ --- говнокод
	ret := &exprParserCtx{
		ctx:         ctx,
		rule:        rule,
		setMapping:  setMapping,
		setElements: setElements,
	}
	ret.idleState = idleState{pctx: ret}
	ret.setState(ret.idleState)
	return ret
}

func (pctx *exprParserCtx) parseMeta(meta *expr.Meta) {
	pctx.state.parseMeta(meta)
}

func (pctx *exprParserCtx) parseCmp(cmp *expr.Cmp) {
	pctx.state.parseCmp(cmp)
}

func (pctx *exprParserCtx) parsePayload(payload *expr.Payload) {
	pctx.state.parsePayload(payload)
}

func (pctx *exprParserCtx) parseLookup(lookup *expr.Lookup) {
	pctx.state.parseLookup(lookup)
}

func (pctx *exprParserCtx) parseVerdict(verdict *expr.Verdict) {
	action := pctx.rule.Action
	switch verdict.Kind {
	// TODO: add `masquerade` as nftables-exporter do
	case expr.VerdictDrop, expr.VerdictAccept:
		action = verdictKind2str(verdict.Kind)
	default:
	}
	pctx.rule.Action = action
}

func (pctx *exprParserCtx) setState(s parserState) {
	pctx.state = s
}

func (pctx *exprParserCtx) toIdle() {
	pctx.state = pctx.idleState
}
