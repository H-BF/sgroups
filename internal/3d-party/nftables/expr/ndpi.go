package expr

import (
	"encoding/binary"

	"bufio"
	"fmt"
	"os"
	"strings"

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
	NFTNL_EXPR_NDPI_PROTO    = 0x4
)

const (
	NDPI_GIT_RELEASE   = "4.3.0-8-6ae5394"
	NDPI_NUM_BITS      = 512
	NDPI_NUM_BITS_MASK = (512 - 1)
	NDPI_BITS          = 32 // sizeof(uint32) * 8
)

type ndpi_ndpi_mask uint32

func howmanybits(x, y int) int {
	return ((x) + ((y) - 1)) / (y)
}

const NDPI_NUM_FDS_BITS = ((NDPI_NUM_BITS) + ((NDPI_BITS) - 1)) / (NDPI_BITS) //howmanybits(NDPI_NUM_BITS, NDPI_BITS)

type ndpi_protocol_bitmask_struct_t struct {
	fds_bits [NDPI_NUM_FDS_BITS]ndpi_ndpi_mask
}

type NDPI_PROTOCOL_BITMASK = ndpi_protocol_bitmask_struct_t

func NDPI_SET(p *NDPI_PROTOCOL_BITMASK, n uint32) {
	p.fds_bits[n/NDPI_BITS] |= 1 << (n % NDPI_BITS)
}

func NDPI_CLR(p *NDPI_PROTOCOL_BITMASK, n uint32) {
	p.fds_bits[n/NDPI_BITS] &= ^(1 << (n % NDPI_BITS))
}

func NDPI_ISSET(p *NDPI_PROTOCOL_BITMASK, n uint32) bool {
	return (p.fds_bits[n/NDPI_BITS] & (1 << (n % NDPI_BITS))) != 0
}

func NDPI_ZERO(p *NDPI_PROTOCOL_BITMASK) {
	for i := range p.fds_bits {
		p.fds_bits[i] = 0
	}
}

func NDPI_ONE(p *NDPI_PROTOCOL_BITMASK) {
	for i := range p.fds_bits {
		p.fds_bits[i] = ^ndpi_ndpi_mask(0)
	}
}

func NDPI_COMPARE_PROTOCOL_TO_BITMASK(bmask NDPI_PROTOCOL_BITMASK, value uint32) bool {
	return NDPI_ISSET(&bmask, value&NDPI_NUM_BITS_MASK)
}

func NDPI_ADD_PROTOCOL_TO_BITMASK(bmask *NDPI_PROTOCOL_BITMASK, value uint32) {
	NDPI_SET(bmask, value&NDPI_NUM_BITS_MASK)
}

func NDPI_DEL_PROTOCOL_FROM_BITMASK(bmask *NDPI_PROTOCOL_BITMASK, value uint32) {
	NDPI_CLR(bmask, value&NDPI_NUM_BITS_MASK)
}

const NDPI_PROTOCOL_UNKNOWN = 0

const (
	NFTA_NDPI_UNSPEC = iota
	NFTA_NDPI_PROTO
	NFTA_NDPI_FLAGS
	NFTA_NDPI_HOSTNAME
)

type Ndpi struct {
	NdpiFlags uint16

	proto    NDPI_PROTOCOL_BITMASK
	ProtoStr string

	// Equivalent to expression flags.
	// Indicates that an option is set by setting a bit
	Key uint32

	Hostname []byte
}

var (
	protoStr      = make([]string, NDPI_NUM_BITS)
	protoDisabled = make([]bool, NDPI_NUM_BITS+1)
)

func (dpi *Ndpi) ndpiProtoStrToArr(proto string) error {
	arrProto := strings.Split(strings.ToLower(proto), ",")
	for _, prEl := range arrProto {
		num := -1
		op := true
		if strings.HasPrefix(prEl, "-") {
			op = false
			prEl = strings.TrimPrefix(prEl, "-")
		}

		for i := 0; i < NDPI_NUM_BITS; i++ {
			if len(protoStr[i]) > 0 && strings.Compare(protoStr[i], prEl) == 0 {
				num = i
				break
			}
		}
		if num < 0 {
			if prEl != "all" {
				return fmt.Errorf("Unknown proto '%s'", prEl)
			}
			for i := 0; i < NDPI_NUM_BITS; i++ {
				if len(protoStr[i]) > 0 && !strings.HasPrefix(protoStr[i], "badproto_") && (protoDisabled[i] == false) {
					if op == true {
						NDPI_ADD_PROTOCOL_TO_BITMASK(&dpi.proto, uint32(i))
					} else {
						NDPI_DEL_PROTOCOL_FROM_BITMASK(&dpi.proto, uint32(i))
					}
				}
			}
		} else {

			if protoDisabled[num] {
				return fmt.Errorf("Disabled proto '%s'\n", prEl)
			}

			if op == true {
				NDPI_ADD_PROTOCOL_TO_BITMASK(&dpi.proto, uint32(num))
			} else {
				NDPI_DEL_PROTOCOL_FROM_BITMASK(&dpi.proto, uint32(num))
			}
		}

	}
	return nil
}

func (e *Ndpi) marshal(fam byte) ([]byte, error) {

	attrs := make([]netlink.Attribute, 0)

	if e.Key&NFTNL_EXPR_NDPI_HOSTNAME != 0 {
		hostname := append(e.Hostname, '\x00')
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

	if e.Key&NFTNL_EXPR_NDPI_PROTO != 0 {
		err := e.ndpiProtoStrToArr(e.ProtoStr)
		if err != nil {
			return nil, err
		}
		if !NDPI_BITMASK_IS_EMPTY(&e.proto) {
			byteArray := make([]byte, len(e.proto.fds_bits)*4)
			for i, num := range e.proto.fds_bits {
				binary.LittleEndian.PutUint32(byteArray[i*4:], uint32(num))
			}
			attrs = append(attrs, netlink.Attribute{
				Type: NFTA_NDPI_PROTO,
				Data: byteArray,
			})
		}
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
			e.Hostname = data[:len(data)-1]
		case NFTA_NDPI_PROTO:
			for i := 0; i < len(data)/4; i++ {
				e.proto.fds_bits[i] = ndpi_ndpi_mask(binaryutil.BigEndian.Uint32(data[i*4:]))
			}
		}
	}
	return ad.Err()
}

func NftNdpiInit() error {
	return nftNdpiGetProtos(protoStr, protoDisabled)
}

func nftNdpiGetProtos(protoStr []string, protoDisabled []bool) error {
	pname := ""
	var mark string
	var index uint32

	f_proto, err := os.Open("/proc/net/xt_ndpi/proto")
	if err != nil {
		return fmt.Errorf("xt_ndpi kernel module not found!")
	}
	defer f_proto.Close()

	index = 0

	scanner := bufio.NewScanner(f_proto)

	for scanner.Scan() {
		line := scanner.Text()

		if pname == "" && strings.Contains(line, "#id") {

			vs := strings.Index(line, "#version")
			if vs < 0 {
				return fmt.Errorf("xt_ndpi version not found!")
			}

			vs = strings.Index(line, NDPI_GIT_RELEASE)
			if vs < 0 {
				return fmt.Errorf("xt_ndpi version mismatch!")
			}
			pname = " "
			continue
		}
		if pname == "" {
			continue
		}
		n, err := fmt.Sscanf(line, "%x %s %s", &index, &mark, &pname)

		if err != nil || n != 3 {
			continue
		}

		if index >= NDPI_NUM_BITS {
			continue
		}
		protoDisabled[index] = strings.Contains(mark, "disabled")
		protoStr[index] = pname
	}

	if index >= NDPI_NUM_BITS {
		return fmt.Errorf("xt_ndpi version mismatch!")
	}

	return nil
}

func NDPI_BITMASK_IS_EMPTY(a *NDPI_PROTOCOL_BITMASK) bool {
	for i := 0; i < NDPI_NUM_FDS_BITS; i++ {
		if a.fds_bits[i] != 0 {
			return false
		}
	}
	return true
}
