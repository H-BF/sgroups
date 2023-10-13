package provider

import (
	"fmt"
	"strings"

	"github.com/H-BF/protos/pkg/api/common"
	protos "github.com/H-BF/protos/pkg/api/sgroups"
	"github.com/pkg/errors"
)

type (
	ruleKey struct {
		proto    common.Networks_NetIP_Transport
		from, to string
	}
)

func fromFqdnRule(rule *protos.FqdnRule) ruleKey {
	return ruleKey{
		proto: rule.GetTransport(),
		from:  rule.GetSgFrom(),
		to:    rule.GetFQDN(),
	}
}

func restoreSgToFqdnKey(key string) (ruleKey, error) {
	var ret ruleKey
	idx := strings.Index(key, ":")
	if idx == -1 {
		return ret, errors.Errorf("bad proto in key: %s", key)
	}
	protoName, rest := key[:idx], key[idx+1:]
	protoValue := common.Networks_NetIP_Transport_value[strings.ToUpper(protoName)]
	ret.proto = common.Networks_NetIP_Transport(protoValue)

	from, rest, err := extractPart("sg", rest)
	if err != nil {
		return ret, err
	}
	ret.from = from

	to, rest, err := extractPart("fqdn", rest)
	if err != nil {
		return ret, err
	}
	ret.to = to

	if len(rest) != 0 {
		return ret, errors.Errorf("unexpected rest data: %s", rest)
	}

	return ret, nil
}

func (k ruleKey) sgToFqdnKey() string {
	return k.buildKey("%s:sg(%s)fqdn(%s)")
}

func (k ruleKey) sgToSgKey() string {
	return k.buildKey("%s:sg(%s)sg(%s)")
}

func (k ruleKey) buildKey(template string) string {
	protoValue := int32(k.proto)
	ruleProto := common.Networks_NetIP_Transport_name[protoValue]
	return fmt.Sprintf(template, strings.ToLower(ruleProto), k.from, k.to)
}

func extractPart(partName, s string) (part string, rest string, err error) {
	s, found := strings.CutPrefix(s, partName+"(")
	if !found {
		return part, rest, errors.Errorf("part `%s` not found", partName)
	}
	idx := strings.Index(s, ")")
	if idx == -1 {
		return part, rest, errors.New("closing parenthesis not found")
	}
	return s[:idx], s[idx+1:], nil
}
