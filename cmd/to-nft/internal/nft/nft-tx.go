package nft

import (
	"net"
	"sync"

	"github.com/c-robinson/iplib"
	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
	"github.com/vishvananda/netns"
)

type nfTablesTx struct {
	*nftLib.Conn
	commitOnce sync.Once
}

func nfTx(netNS string) (*nfTablesTx, error) {
	const api = "connect to nft"

	opts := []nftLib.ConnOption{nftLib.AsLasting()}
	if len(netNS) > 0 {
		n, e := netns.GetFromName(netNS)
		if e != nil {
			return nil, errors.WithMessagef(e,
				"%s: accessing netns '%s'", api, netNS)
		}
		opts = append(opts, nftLib.WithNetNSFd(int(n)))
		defer n.Close()
	}
	c, e := nftLib.New(opts...)
	if e != nil {
		return nil, errors.WithMessage(e, api)
	}
	return &nfTablesTx{Conn: c}, nil
}

// Close impl 'Closer'
func (tx *nfTablesTx) Close() error {
	c := tx.Conn
	tx.commitOnce.Do(func() {
		_ = c.CloseLasting()
	})
	return nil
}

// FlushAndClose does flush and close
func (tx *nfTablesTx) FlushAndClose() error {
	c := tx.Conn
	err := net.ErrClosed
	tx.commitOnce.Do(func() {
		err = tx.Flush()
		_ = c.CloseLasting()
	})
	return err
}

var (
	_ = ipToReverseBytes
)

func reverseBytes(p []byte) {
	for i, j := 0, len(p)-1; i < j && j >= 0; i, j = i+1, j-1 {
		p[i], p[j] = p[j], p[i]
	}
}

func ipToReverseBytes(ip net.IP) []byte {
	ipAsInt := iplib.IPToBigint(ip)
	b := ipAsInt.Bytes()
	reverseBytes(b)
	return b
}
