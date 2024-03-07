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
			protos.Rule | protos.FqdnRule |
			protos.SgIcmpRule | protos.SgSgIcmpRule |
			protos.CidrSgRule | protos.CidrSgIcmpRule |
			protos.SgSgRule | protos.IESgSgIcmpRule
	}

	// BackendRcList -
	BackendRcList[B BackendRC] []string

	// BackendState -
	BackendState struct {
		Networks        BackendRcList[protos.Network]        `yaml:"networks"`
		SecGroups       BackendRcList[protos.SecGroup]       `yaml:"sec-groups"`
		SgSgRules       BackendRcList[protos.Rule]           `yaml:"sg-sg-rules"`
		SgFqdnRules     BackendRcList[protos.FqdnRule]       `yaml:"sg-fqdn-rules"`
		SgIcmpRules     BackendRcList[protos.SgIcmpRule]     `yaml:"sg-icmp-rules"`
		SgSgIcmpRules   BackendRcList[protos.SgSgIcmpRule]   `yaml:"sg-sg-icmp-rules"`
		CidrSgRules     BackendRcList[protos.CidrSgRule]     `yaml:"cidr-sg-rules"`
		CidrSgIcmpRules BackendRcList[protos.CidrSgIcmpRule] `yaml:"cidr-sg-icmp-rules"`
		IESgSgRules     BackendRcList[protos.SgSgRule]       `yaml:"ie-sg-sg-rules"`
		IESgSgIcmpRules BackendRcList[protos.IESgSgIcmpRule] `yaml:"ie-sg-sg-icmp-rules"`
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

// Encode -
func (rcl *BackendRcList[B]) Encode(objs []*B) {
	*rcl = nil
	for _, o := range objs {
		d, e := protojson.Marshal(any(o).(protoreflect.ProtoMessage))
		if e != nil {
			panic(e)
		}
		*rcl = append(*rcl, unsafe.String(unsafe.SliceData(d), len(d)))
	}
}

// Backend2Domain -
func Backend2Domain[B BackendRC, D DomainRC](in []*B, ret *DomainRcList[D]) {
	for _, p := range in {
		var v D
		proto2domain(p, &v)
		*ret = append(*ret, v)
	}
}
