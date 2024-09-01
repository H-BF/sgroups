package sgroups

import (
	"bytes"
	"crypto/md5" //nolint:gosec
	"io"
	"unsafe"

	netrc "github.com/H-BF/corlib/pkg/net/resources"
)

// PortSource represents a single port num "12" or port range "12-22" as string
type PortSource = netrc.PortSource

func args2slice[T any](args ...T) []T {
	return args
}

func packPortRanges(pr PortRanges, w io.Writer) {
	var bounds [2]struct {
		v  PortNumber
		ex bool
	}
	sl := unsafe.Slice((*byte)(unsafe.Pointer(&bounds)), unsafe.Sizeof(bounds))
	pr.Iterate(func(r PortRange) bool {
		for i, b := range args2slice(r.Normalize().Bounds()) {
			bounds[i].v, bounds[i].ex = b.GetValue()
		}
		_, _ = w.Write(sl)
		return true
	})
}

func packSGRulePorts(pr SGRulePorts, w io.Writer) {
	for _, item := range args2slice(pr.S, pr.D) {
		packPortRanges(item, w)
		_, _ = w.Write([]byte{'|'})
	}
}

// AreRulePortsEq -
func AreRulePortsEq(l, r []SGRulePorts) bool {
	if len(l) != len(r) {
		return false
	}
	type key = [md5.Size]byte
	type dict = map[key]int
	ld := make(dict, len(l))
	rd := make(dict, len(r))
	dst := args2slice(&ld, &rd)
	buf := bytes.NewBuffer(nil)
	for i, item := range args2slice(l, r) {
		d := *dst[i]
		for _, pr := range item {
			buf.Reset()
			packSGRulePorts(pr, buf)
			d[md5.Sum(buf.Bytes())]++ //nolint:gosec
		}
	}
	if len(ld) != len(rd) {
		return false
	}
	for k, v := range ld {
		if v != rd[k] {
			return false
		}
	}
	return true
}
