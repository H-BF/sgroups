package nft

import (
	"fmt"
	"strings"

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
