package nft

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/H-BF/corlib/pkg/backoff"
	"github.com/ahmetb/go-linq/v3"
	"github.com/c-robinson/iplib"
	nftLib "github.com/google/nftables"
)

type (
	nameUtils struct{}
	setsUtils struct{}
)

const (
	// MainTablePrefix -
	MainTablePrefix = "main"
)

var (
	reMainTable = regexp.MustCompile(`^` + MainTablePrefix + `(-\d+)?$`)

	nextUnixEpochInSeconds func() int64
)

func init() {
	var (
		prev int64
		m    sync.Mutex
	)
	nextUnixEpochInSeconds = func() int64 {
		const milli = 1000
		m.Lock()
		defer m.Unlock()
		for {
			d := time.Now().UnixMilli()
			delta := d - prev
			if delta > milli {
				prev = d
				break
			}
			time.Sleep(time.Duration((milli - delta) * int64(time.Millisecond)))
		}
		return prev / milli
	}
}

func (nameUtils) genMainTableName() string {
	return fmt.Sprintf("%s-%v", MainTablePrefix, nextUnixEpochInSeconds())
}

func (nameUtils) isLikeMainTableName(s string) bool {
	return reMainTable.MatchString(s)
}

func (nameUtils) nameOfInOutChain(dir direction, sgName string) string {
	return fmt.Sprintf(
		"%s-%s",
		tern(dir == dirIN, chnIngressINPUT, chnEgressPOSTROUTING), sgName,
	)
}

func (nameUtils) nameOfFqdnNetSet(ipV ipVersion, domain model.FQDN) string {
	return fmt.Sprintf("NetIPv%v-fqdn-%s", ipV, strings.ToLower(domain.String()))
}

func (nameUtils) nameOfNetSet(ipV ipVersion, sgName string) string {
	if sgName = strings.TrimSpace(sgName); len(sgName) == 0 {
		panic("no 'SG' name in arguments")
	}
	return fmt.Sprintf("NetIPv%v-%s", ipV, sgName)
}

func (nameUtils) nameOfSG2SGRuleDetails(tp model.NetworkTransport, sgFrom, sgTo string) string {
	if sgFrom = strings.TrimSpace(sgFrom); len(sgFrom) == 0 {
		panic("no 'SGFrom' name in arguments")
	}
	if sgTo = strings.TrimSpace(sgTo); len(sgTo) == 0 {
		panic("no 'SGTo' name in arguments")
	}
	//                 [tcp|udp]-sgFrom-sgTo
	return fmt.Sprintf("%s-%s-%s", tp, sgFrom, sgTo)
}

func (nameUtils) nameOfSG2FQDNRuleDetails(tp model.NetworkTransport, sgFrom string, domain model.FQDN) string {
	if sgFrom = strings.TrimSpace(sgFrom); len(sgFrom) == 0 {
		panic("no 'SGFrom' name in arguments")
	}
	if e := domain.Validate(); e != nil {
		panic(e)
	}
	//                 [tcp|udp]-sgFrom-domain-fqdn
	return fmt.Sprintf("%s-%s-%s-fqdn", tp, sgFrom, domain)
}

func (nameUtils) nameCidrSgRuleDetails(rule *model.CidrSgRule) string {
	return rule.ID.String()
}

func (nameUtils) nameSgIeSgRuleDetails(rule *model.SgSgRule) string {
	return rule.ID.String()
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
		default:
			return nil
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

func (setsUtils) transormPortRanges(pr model.PortRanges) (ret [][2]model.PortNumber) {
	ret = make([][2]model.PortNumber, 0, pr.Len())
	pr.Iterate(func(r model.PortRange) bool {
		a, b := r.Bounds()
		var x [2]model.PortNumber
		x[0], _ = a.AsIncluded().GetValue()
		x[1], _ = b.AsIncluded().GetValue()
		ret = append(ret, x)
		return true
	})
	return ret
}

func (u setsUtils) makeAccPorts(prr []model.SGRulePorts) (ret []accports) {
	linq.From(prr).
		Select(func(i any) any {
			p := i.(model.SGRulePorts)
			return accports{
				dp: u.transormPortRanges(p.D),
				sp: u.transormPortRanges(p.S),
			}
		}).
		Where(func(i any) bool {
			accp := i.(accports)
			return len(accp.sp) != 0 || len(accp.dp) != 0
		}).ToSlice(&ret)
	return ret
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

func isIn[T comparable](test T, vals []T) bool {
	for i := range vals {
		if test == vals[i] {
			return true
		}
	}
	return false
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

// MakeBatchBackoff -
func MakeBatchBackoff() backoff.Backoff {
	return backoff.ExponentialBackoffBuilder().
		WithMultiplier(1.3).                       //nolint:gomnd
		WithRandomizationFactor(0).                //nolint:gomnd
		WithMaxElapsedThreshold(20 * time.Second). //nolint:gomnd
		Build()
}
