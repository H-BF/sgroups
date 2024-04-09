package nftables_collector

import (
	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const (
	OffsetV4Saddr uint32 = 12
	OffsetV4Daddr uint32 = 16
	OffsetV6Saddr uint32 = 8
	OffsetV6Daddr uint32 = 24
)

const (
	OffsetSport = 0
	OffsetDport = 2
)

func metaKey2string(k expr.MetaKey) string {
	vals := []string{
		"LEN", "PROTOCOL", "PRIORITY", "MARK", "IIF", "OIF", "IIFNAME", "OIFNAME",
		"IIFTYPE", "OIFTYPE", "SKUID", "SKGID", "NFTRACE", "RTCLASSID", "SECMARK",
		"NFPROTO", "L4PROTO", "BRIIIFNAME", "BRIOIFNAME", "PKTTYPE", "CPU", "IIFGROUP",
		"OIFGROUP", "CGROUP", "PRANDOM"}

	if k < 0 || expr.MetaKey(len(vals)) <= k {
		return "undef"
	}
	return vals[k]
}

func family2str(f nft.TableFamily) string {
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
	return "unknown"
}

func verdictKind2str(v expr.VerdictKind) string {
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
	return "unknown"
}
