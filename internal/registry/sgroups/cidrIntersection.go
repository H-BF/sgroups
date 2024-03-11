package sgroups

import (
	"bytes"
	"fmt"
	"net"
	"sort"

	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/ahmetb/go-linq/v3"
	"github.com/pkg/errors"
)

type (
	groupKey string

	ref struct {
		id   interface{}
		CIDR net.IPNet
	}

	tableLinqIterator struct {
		MemDbIterator
	}
)

func groupKeyFromRule(i interface{}) (ret interface{}) {
	switch r := i.(type) {
	case *model.IECidrSgRule:
		ret = groupKey(fmt.Sprintf("%s:sg(%s)%s", r.ID.Transport, r.ID.SG, r.ID.Traffic))
	case *model.IECidrSgIcmpRule:
		ret = groupKey(fmt.Sprintf("icmp%v:sg(%s)%s", r.Icmp.IPv, r.SG, r.Traffic))
	default:
		panic(fmt.Sprintf("unsupported type for groupKey: %T", r))
	}
	return ret
}

func elementSelector(i interface{}) (ret interface{}) {
	switch r := i.(type) {
	case *model.IECidrSgRule:
		ret = ref{
			id:   r.ID,
			CIDR: r.ID.CIDR,
		}
	case *model.IECidrSgIcmpRule:
		ret = ref{
			id:   r.ID(),
			CIDR: r.CIDR,
		}
	default:
		panic(fmt.Sprintf("unsupported type for elementSelector: %T", r))
	}
	return ret
}

// Iterate impl linq.Iterable
func (r *tableLinqIterator) Iterate() linq.Iterator {
	return func() (item interface{}, ok bool) {
		item = r.Next()
		ok = item != nil
		return item, ok
	}
}

func errf(objs ...interface{}) error {
	if len(objs) <= 1 {
		return nil
	}
	return errors.Errorf("some rules %s have CIDRS with intersected segments", objs)
}

func detectIntersections(nextGroup linq.Iterator) []any {
	for i, ok := nextGroup(); ok; i, ok = nextGroup() {
		group := i.(linq.Group)
		if len(group.Group) < 2 {
			continue
		}

		sort.Slice(group.Group, func(i, j int) bool {
			iItem, jItem := group.Group[i].(ref), group.Group[j].(ref)
			return bytes.Compare(iItem.CIDR.IP.To16(), jItem.CIDR.IP.To16()) == -1
		})

		prevRef := group.Group[0].(ref)
		for i := 1; i < len(group.Group); i++ {
			rf := group.Group[i].(ref)
			if prevRef.CIDR.Contains(rf.CIDR.IP) || rf.CIDR.Contains(prevRef.CIDR.IP) {
				return []any{prevRef.id, rf.id}
			}
			prevRef = rf
		}
	}
	return nil
}
