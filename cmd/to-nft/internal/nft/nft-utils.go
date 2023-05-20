package nft

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
)

type nameUtils struct{}

func (nameUtils) nameOfNetSet(ipV ipVersion, sgName string) string {
	if sgName = strings.TrimSpace(sgName); len(sgName) == 0 {
		panic("no 'SG' name in arguments")
	}
	return fmt.Sprintf("NetIPv%v-%s", ipV, sgName)
}

func (nameUtils) nameOfPortSet(tp model.NetworkTransport, sgFrom, sgTo string) string {
	if sgFrom = strings.TrimSpace(sgFrom); len(sgFrom) == 0 {
		panic("no 'SGFrom' name in arguments")
	}
	if sgTo = strings.TrimSpace(sgTo); len(sgTo) == 0 {
		panic("no 'SGTo' name in arguments")
	}
	//                 [tcp|udp]-sgFrom-sgTo
	return fmt.Sprintf("%s-%s-%s", tp, sgFrom, sgTo)
}

type stringer func() string

func (s stringer) String() string {
	return s()
}

func tern[t1 any, t2 any](cond bool, a1 t1, a2 t2) any {
	if cond {
		return a1
	}
	return a2
}

func slice2stringer[t any](ar ...t) fmt.Stringer {
	return stringer(func() string {
		b := bytes.NewBuffer(nil)
		for i, o := range ar {
			if i > 0 {
				_, _ = b.WriteString("; ")
			}
			s, _ := interface{}(o).(fmt.Stringer)
			if s == nil {
				s, _ = interface{}(&o).(fmt.Stringer)
			}
			_, _ = fmt.Fprintf(b, "%v", tern(s != nil, s, o))
		}
		return b.String()
	})
}

func val2ptr[T any](val T) *T {
	return &val
}

func zeroEndedS(s string) string {
	const z = "\x00"
	if n := len(s); n > 0 {
		n1 := strings.LastIndex(s, z)
		if n1 >= 0 && (n-n1) == 1 {
			return s
		}
	}
	return s + z
}

func nextSetID() uint32 {
	return atomic.AddUint32(&setID, 1)
}

var setID = rand.Uint32()
