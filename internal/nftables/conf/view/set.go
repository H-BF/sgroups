package view

import (
	"errors"
	"math/big"
	"math/bits"
	"net"

	"github.com/c-robinson/iplib"
	nft "github.com/google/nftables"
)

var (
	errIPAddrLengthMismatch = errors.New("ip addr length mismatch")
	errBadInterval          = errors.New("two consecutive elements with IntervalEnd=true")
)

func setElems2Nets(setElems []nft.SetElement) ([]string, error) {
	var res []string
	var interval []byte
	for _, el := range setElems {
		if el.IntervalEnd {
			if iplib.IsAllZeroes(el.Key) {
				continue
			}
			if len(interval) != 0 {
				return nil, errBadInterval
			}
			interval = el.Key
			continue
		}
		if len(interval) > 0 {
			newNet, err := netFromTwoIP(el.Key, interval)
			if err != nil {
				return nil, err
			}
			res = append(res, newNet)
			interval = nil
			continue
		}
		res = append(res, net.IP(el.Key).String())
	}
	return res, nil
}

func netFromTwoIP(start, end net.IP) (string, error) {
	sInt, eInt := iplib.IPToBigint(start), iplib.IPToBigint(end)
	var res big.Int
	if res.Sub(eInt, sInt).Int64() == 1 { // there is host address
		return net.IP(start).String(), nil
	}
	// otherwise there is subnet
	mask, err := findCommonLongestMask(start, end)
	if err != nil {
		return "", err
	}
	newNet := net.IPNet{
		IP:   start,
		Mask: net.CIDRMask(mask, len(start)*8),
	}
	return newNet.String(), nil
}

// start should be subnet addr and end should be start of next subnet with same mask
func findCommonLongestMask(a, b net.IP) (int, error) {
	var ret int
	if len(a) != len(b) {
		return ret, errIPAddrLengthMismatch
	}
	b = iplib.PreviousIP(b)
	for i := range a {
		xor := a[i] ^ b[i]
		commonPrefix := bits.LeadingZeros8(xor)
		ret += commonPrefix
		if commonPrefix != 8 {
			break
		}
	}
	return ret, nil
}
