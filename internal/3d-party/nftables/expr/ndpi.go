package expr

import (
	"encoding/binary"

	"github.com/google/nftables/binaryutil"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	NFT_NDPI_FLAG_INVERT uint16 = 0x01 << iota
	NFT_NDPI_FLAG_ERROR
	NFT_NDPI_FLAG_M_PROTO
	NFT_NDPI_FLAG_P_PROTO
	NFT_NDPI_FLAG_HAVE_MASTER
	NFT_NDPI_FLAG_HOST
	NFT_NDPI_FLAG_RE
	NFT_NDPI_FLAG_EMPTY
	NFT_NDPI_FLAG_INPROGRESS
	NFT_NDPI_FLAG_JA3S
	NFT_NDPI_FLAG_JA3C
	NFT_NDPI_FLAG_TLSFP
	NFT_NDPI_FLAG_TLSV
	NFT_NDPI_FLAG_UNTRACKED
)

const (
	NFTNL_EXPR_NDPI_HOSTNAME = 0x1
	NFTNL_EXPR_NDPI_FLAGS    = 0x2
)

const (
	NFTA_NDPI_UNSPEC = iota
	NFTA_NDPI_PROTO
	NFTA_NDPI_FLAGS
	NFTA_NDPI_HOSTNAME
)

type Ndpi struct {
	NdpiFlags uint16

	// Equivalent to expression flags.
	// Indicates that an option is set by setting a bit
	Key uint32
	// Hostname string content
	Data []byte
}

func (e *Ndpi) marshal(fam byte) ([]byte, error) {

	attrs := make([]netlink.Attribute, 0)

	if e.Key&NFTNL_EXPR_NDPI_HOSTNAME != 0 {
		hostname := append(e.Data, '\x00')
		attrs = append(attrs, netlink.Attribute{
			Type: NFTA_NDPI_HOSTNAME,
			Data: hostname,
		})
		e.NdpiFlags |= NFT_NDPI_FLAG_HOST
	}

	if e.Key&NFTNL_EXPR_NDPI_FLAGS != 0 {
		attrs = append(attrs, netlink.Attribute{
			Type: NFTA_NDPI_FLAGS,
			Data: binaryutil.BigEndian.PutUint16(e.NdpiFlags),
		})
	}

	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("ndpi\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Ndpi) unmarshal(fam byte, data []byte) error {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		e.Key |= 1 << uint32(ad.Type())
		data := ad.Bytes()
		switch ad.Type() {
		case NFTA_NDPI_FLAGS:
			e.NdpiFlags = binaryutil.BigEndian.Uint16(data)
		case NFTA_NDPI_HOSTNAME:
			// Getting rid of \x00 at the end of string
			e.Data = data[:len(data)-1]
		}
	}
	return ad.Err()
}
