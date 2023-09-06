package nft

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/c-robinson/iplib"
	nftLib "github.com/google/nftables"
)

type (
	nameUtils struct{}
	setsUtils struct{}
)

func (nameUtils) nameOfFqdnNetSet(ipV ipVersion, domain model.FQDN) string {
	return fmt.Sprintf("NetIPv%v-fqdn-%s", ipV, strings.ToLower(domain.String()))
}

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

func (setsUtils) nets2SetElements(nets []net.IPNet, ipV int) []nftLib.SetElement {
	const (
		b32  = 32
		b128 = 128
	)
	var elements []nftLib.SetElement
	for i := range nets {
		nw := nets[i]
		ones, _ := nw.Mask.Size()
		netIf := iplib.NewNet(nw.IP, ones)
		ipLast := iplib.NextIP(netIf.LastAddress())
		switch ipV {
		case iplib.IP4Version:
			ipLast = tern(ones < b32, iplib.NextIP(ipLast), ipLast)
		case iplib.IP6Version:
			ipLast = tern(ones < b128, iplib.NextIP(ipLast), ipLast)
		}
		////TODO: need expert opinion
		//elements = append(elements, nftLib.SetElement{
		//	Key:    nw.IP,
		//	KeyEnd: ipLast,
		//})
		elements = append(elements,
			nftLib.SetElement{
				Key: nw.IP,
			},
			nftLib.SetElement{
				IntervalEnd: true,
				Key:         ipLast,
			})
	}
	return elements
}

type stringer func() string

func (s stringer) String() string {
	return s()
}

func ternAny[t1 any, t2 any](cond bool, a1 t1, a2 t2) any {
	if cond {
		return a1
	}
	return a2
}

func sli[T any](d ...T) []T {
	return d
}

func tern[T any](cond bool, a1, a2 T) T {
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
				s, _ = interface{}(&o).(fmt.Stringer) //nolint:gosec
			}
			_, _ = fmt.Fprintf(b, "%v", ternAny(s != nil, s, o))
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

var setID = rand.Uint32() //nolint:gosec
