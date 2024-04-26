package parser

import (
	"errors"
	"github.com/H-BF/corlib/logger"
	dkt "github.com/H-BF/sgroups/internal/dict"
	"github.com/H-BF/sgroups/internal/nftables/conf"
	hlp "github.com/H-BF/sgroups/internal/nftables/helpers"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"strconv"
)

// Rule - parsed chain rule
type Rule struct {
	Chain      string
	Table      string
	Family     string
	Comment    string
	Action     string
	Handle     string
	Interfaces struct {
		Input  []string
		Output []string
	}
	Addresses struct {
		Source      []string
		Destination []string
	}
	Ports struct {
		Source      []string
		Destination []string
	}
	*Counter
}

type Counter struct {
	Bytes   float64
	Packets float64
}

func From(nfRule *nftables.Rule, sets dkt.HDict[string, conf.NfSet], log *logger.TypeOfLogger) (*Rule, error) {
	r := Rule{
		Chain:   nfRule.Chain.Name,
		Family:  hlp.TableFamily2S(nfRule.Table.Family),
		Table:   nfRule.Table.Name,
		Comment: "empty",
		Action:  "policy",
		Handle:  strconv.FormatUint(nfRule.Handle, 10),
	}

	parserCtx := &exprParserCtx{
		rule:      &r,
		setsState: sets,
	}
	parserCtx.setState(idleState{parserCtx})

	for _, e := range nfRule.Exprs {
		// TODO: parse rule comments
		switch v := e.(type) {
		case *expr.Counter:
			if r.Counter != nil {
				return nil, errors.New("counter already exists")
			}
			r.Counter = new(Counter)
			r.Counter.Bytes = float64(v.Bytes)
			r.Counter.Packets = float64(v.Packets)
		case *expr.Lookup:
			parserCtx.parseLookup(v)
		case *expr.Cmp:
			parserCtx.parseCmp(v)
		case *expr.Payload:
			parserCtx.parsePayload(v)
		case *expr.Verdict:
			switch v.Kind {
			// TODO: add `masquerade` as nftables-exporter do
			case expr.VerdictDrop, expr.VerdictAccept:
				r.Action = hlp.VerdictKind2S(v.Kind)
			default:
			}
		case *expr.Meta:
			parserCtx.parseMeta(v)
		default:
			debug(log, "*** Any{Type: %T}", e)
		}
	}
	return &r, nil
}

func debug(log *logger.TypeOfLogger, fmtMsg string, args ...any) {
	if log != nil {
		log.Debugf(fmtMsg, args...)
	}
}
