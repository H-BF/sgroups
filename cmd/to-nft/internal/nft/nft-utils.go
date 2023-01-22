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

func (nameUtils) nameOfPortSet(tp model.NetworkTransport, sgFrom, sgTo string, isDest bool) string {
	if sgFrom = strings.TrimSpace(sgFrom); len(sgFrom) == 0 {
		panic("no 'SGFrom' name in arguments")
	}
	if sgTo = strings.TrimSpace(sgTo); len(sgTo) == 0 {
		panic("no 'SGTo' name in arguments")
	}
	dir := 's'
	if isDest {
		dir = 'd'
	}
	//                 [s:d]-[tcp|udp]-sgFrom-sgTo
	return fmt.Sprintf("%c-%s-%s-%s", dir, tp, sgFrom, sgTo)
}
