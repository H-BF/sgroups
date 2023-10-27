package fixtures

import (
	"unsafe"

	protos "github.com/H-BF/protos/pkg/api/sgroups"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type (
	// BackendRC -
	BackendRC interface {
		protos.Network | protos.SecGroup |
			protos.Rule | protos.FqdnRule
	}

	// BackendRcList -
	BackendRcList[B BackendRC] []string

	// BackendState -
	BackendState struct {
		Networks    BackendRcList[protos.Network]  `yaml:"networks"`
		SecGroups   BackendRcList[protos.SecGroup] `yaml:"sec-groups"`
		SgSgRules   BackendRcList[protos.Rule]     `yaml:"sg-sg-rules"`
		SgFqdnRules BackendRcList[protos.FqdnRule] `yaml:"sg-fqdn-rules"`
	}
)

// Decode -
func (rcl BackendRcList[B]) Decode() (ret []*B) {
	for _, src := range rcl {
		v := new(B)
		p := any(v).(protoreflect.ProtoMessage)
		s := unsafe.Slice(unsafe.StringData(src), len(src))
		if e := protojson.Unmarshal(s, p); e != nil {
			panic(e)
		}
		ret = append(ret, v)
	}
	return ret
}

// Backend2Domain -
func Backend2Domain[B BackendRC, D DomainRC](in []*B, ret *DomainRcList[D]) {
	for _, p := range in {
		var v D
		proto2domain(p, &v)
		*ret = append(*ret, v)
	}
}
