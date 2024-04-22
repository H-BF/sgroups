package hlp

import (
	"fmt"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// MetaKey2S -
func MetaKey2S(k expr.MetaKey) string {
	vals := [...]string{
		"len", "protocol", "priority", "mark", "iif", "oif", "iifname", "oifname",
		"iiftype", "oiftype", "skuid", "skgid", "nftrace", "rtclassid", "secmark",
		"nfproto", "l4proto", "briiifname", "brioifname", "pkttype", "cpu", "iifgroup",
		"oifgroup", "cgroup", "prandom",
	}
	if n := expr.MetaKey(len(vals)); k >= n {
		return fmt.Sprintf("meta-key(%v)", k)
	}
	return vals[k]
}

// TableFamily2S -
func TableFamily2S(f nft.TableFamily) string {
	switch f {
	case nft.TableFamilyUnspecified:
		return "unspec"
	case nft.TableFamilyINet:
		return "inet"
	case nft.TableFamilyIPv4:
		return "ip"
	case nft.TableFamilyIPv6:
		return "ip6"
	case nft.TableFamilyARP:
		return "arp"
	case nft.TableFamilyNetdev:
		return "netdev"
	case nft.TableFamilyBridge:
		return "bridge"
	}
	return fmt.Sprintf("table-family(%v)", f)
}

// VerdictKind2S -
func VerdictKind2S(v expr.VerdictKind) string {
	switch v {
	case expr.VerdictReturn:
		return "return"
	case expr.VerdictGoto:
		return "goto"
	case expr.VerdictJump:
		return "jump"
	case expr.VerdictBreak:
		return "break"
	case expr.VerdictContinue:
		return "continue"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictStolen:
		return "stolen"
	case expr.VerdictQueue:
		return "queue"
	case expr.VerdictRepeat:
		return "repeat"
	case expr.VerdictStop:
		return "stop"
	}
	return fmt.Sprintf("verdict(%v)", v)
}
