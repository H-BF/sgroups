package main

import (
	"context"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"net"

	"github.com/H-BF/corlib/logger"
	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type oldExprParserCtx struct {
	ctx         context.Context
	extractData parserExtractData
	extractF    func(p *oldExprParserCtx, exp expr.Any) error

	rule *nftablesRule

	setElements map[string][]nft.SetElement
}

type parserExtractData uint32

const (
	parserExtractUndef parserExtractData = iota
	parserExtractMeta
	parserExtractFunction
)

func (p *oldExprParserCtx) parseLookup(lookup *expr.Lookup, prevExpr expr.Any) {
	if err := p.extractF(p, lookup); err != nil {
		logger.Debugf(p.ctx, "parsing Lookup err: %v", err)
		p.extractF = noopExtract
	}
	// TODO: проверять анонимность сета, если нет то добавить вместо адреса его имя
	switch p.extractData {
	case parserExtractMeta:
		fallthrough
	default:
		logger.Debugf(p.ctx, "default: Lookup{%+v}, parserState:%v, prev expr: {t:%T, v:%+v}",
			lookup, p.extractData, prevExpr, prevExpr)
	}
}

func (p *oldExprParserCtx) parseCmp(cmp *expr.Cmp, prevExpr expr.Any) {
	switch p.extractData {
	case parserExtractFunction:
		if err := p.extractF(p, cmp); err != nil {
			logger.Debugf(p.ctx, "parsing Cmp err: %v", err)
			p.extractF = noopExtract
		}
	case parserExtractMeta:
		meta, ok := prevExpr.(*expr.Meta)
		if !ok {
			logger.Debugf(p.ctx, "wrong use parserExtractMeta: prev expr: {t:%T, v:%+v}", prevExpr, prevExpr)
		} else {
			switch meta.Key {
			case expr.MetaKeyNFPROTO:
				if len(cmp.Data) != 1 {
					logger.Debugf(p.ctx, "wrong bytes count: %d", len(cmp.Data))
					return
				}
				switch cmp.Data[0] {
				case unix.NFPROTO_IPV4:
					p.extractData = parserExtractFunction
					p.extractF = extractIPv4
				case unix.NFPROTO_IPV6:
					p.extractData = parserExtractFunction
					p.extractF = extractIPv6
				default:
					logger.Debugf(p.ctx, "unexpected NFPROTO family: %s", family2str(nft.TableFamily(cmp.Data[0])))
					return
				}

			case expr.MetaKeyL4PROTO:
			case expr.MetaKeyIIFNAME:
			case expr.MetaKeyOIFNAME:
			default:
				logger.Debugf(p.ctx, "unexpected Meta Key: %s", metaKey2string(meta.Key))
			}
		}
	default:
		logger.Debugf(p.ctx, "default: Cmp{Op:%s, Register:%v, Data:%v}, prev expr: {t:%T, v:%+v}",
			cmpOp2string(cmp.Op), cmp.Register, cmp.Data, prevExpr, prevExpr)
	}
}

func (p *oldExprParserCtx) parseMeta(_ *expr.Meta) {
	p.extractData = parserExtractMeta
}

func (p *oldExprParserCtx) parsePayload(payload *expr.Payload) {
	if payload.OperationType != expr.PayloadLoad {
		return
	}
	switch p.extractData {
	case parserExtractFunction:
		if err := p.extractF(p, payload); err != nil {
			logger.Debugf(p.ctx, "parsing Payload err: %v", err)
			p.extractF = noopExtract
		}
	default:
		logger.Debugf(p.ctx, "parse payload expects function extractor but got: %v", p.extractData)
	}
}

func extractIPv4(p *oldExprParserCtx, exp expr.Any) error {
	payload, ok := exp.(*expr.Payload)
	if !ok {
		return errors.Errorf("expected expr.Payload but got: %T", exp)
	}
	if payload.Base != expr.PayloadBaseNetworkHeader {
		return errors.New("payload trying parse IP4 from wrong header")
	}
	var arr []string
	switch payload.Offset {
	case OffsetV4Saddr:
		arr = p.rule.Addresses.Source
	case OffsetV4Daddr:
		arr = p.rule.Addresses.Destination
	}

	p.extractData = parserExtractFunction
	p.extractF = func(p *oldExprParserCtx, exp expr.Any) error {
		defer func() {
			p.extractData = parserExtractUndef
		}()
		switch v := exp.(type) {
		case *expr.Lookup:
			nets, err := setElems2Nets(p.setElements[v.SetName])
			if err != nil {
				logger.Debugf(p.ctx, "Lookup parse err: %v", err)
			} else {
				arr = append(arr, nets...)
			}
		case *expr.Cmp:
			arr = append(arr, net.IP(v.Data).String())
		default:
			logger.Debugf(p.ctx, "ip extraction expected Cmp or Lookup, but got: %T", exp)
		}
		return nil
	}
	return nil
}

func extractIPv6(p *oldExprParserCtx, exp expr.Any) error {
	payload, ok := exp.(*expr.Payload)
	if !ok {
		return errors.Errorf("expected expr.Payload but got: %T", exp)
	}
	if payload.Base != expr.PayloadBaseNetworkHeader {
		return errors.New("payload trying parse IP6 from wrong header")
	}
	switch payload.Offset {
	case OffsetV6Saddr:
		p.extractData = parserExtractUndef
	case OffsetV6Daddr:
		p.extractData = parserExtractUndef
	}
	return nil
}

func noopExtract(_ *oldExprParserCtx, _ expr.Any) error {
	return nil
}
