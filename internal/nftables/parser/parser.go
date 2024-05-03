package parser

import (
	dkt "github.com/H-BF/sgroups/internal/dict"
	"github.com/H-BF/sgroups/internal/nftables/conf"

	"github.com/google/nftables/expr"
)

type exprParserCtx struct {
	rule  *Rule
	state parserState

	setsState dkt.HDict[string, conf.NfSet]
}

func (pctx *exprParserCtx) setState(s parserState) {
	pctx.state = s
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
