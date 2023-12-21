package expr

import (
	"encoding/binary"
	"regexp"
	"strconv"

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
	//Version of the ndpi
	NDPI_GIT_RELEASE = "4.3.0-8-6ae5394"
	//Number of ndpi protocols
	NDPI_NUM_BITS = 512
	//Mask for available ndpi protocols
	NDPI_NUM_BITS_MASK = (512 - 1)
	//Number of bits to describe one protocol
	NDPI_BITS = 32 // sizeof(uint32) * 8
)

type ndpiMaskType = uint32

const NDPI_NUM_FDS_BITS = (NDPI_NUM_BITS + (NDPI_BITS - 1)) / NDPI_BITS

type ndpiProtoBitmask struct {
	fds_bits [NDPI_NUM_FDS_BITS]ndpiMaskType
}

// Set ndpi protocol bit to bitmask
func (p *ndpiProtoBitmask) set(n uint32) {
	p.fds_bits[n/NDPI_BITS] |= 1 << (n % NDPI_BITS)
}

// Clear ndpi protocol bit form bitmask
func (p *ndpiProtoBitmask) clr(n uint32) {
	p.fds_bits[n/NDPI_BITS] &= ^(1 << (n % NDPI_BITS))
}

// Check if ndpi protocol bit is set
func (p *ndpiProtoBitmask) test(n uint32) bool {
	return (p.fds_bits[n/NDPI_BITS] & (1 << (n % NDPI_BITS))) != 0
}

// Check if protocols were set
func (p *ndpiProtoBitmask) compareProtocol(value uint32) bool {
	return p.test(value & NDPI_NUM_BITS_MASK)
}

// Add protocol to bitmask
func (p *ndpiProtoBitmask) addProtocol(value uint32) {
	p.set(value & NDPI_NUM_BITS_MASK)
}

// Delete protocol from bitmask
func (p *ndpiProtoBitmask) delProtocol(value uint32) {
	p.clr(value & NDPI_NUM_BITS_MASK)
}

// Check if ndpi protocol bitmask is empty
func (p *ndpiProtoBitmask) isEmpty() bool {
	return p.fds_bits == ndpiProtoBitmask{}.fds_bits
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

	Protocols []string

	// Equivalent to expression flags.
	// Indicates that an option is set by setting a bit
	Key uint32

	Hostname string
}

func (dpi *Ndpi) bitmaskToProtocols(mask ndpiProtoBitmask) {
	dpi.Protocols = make([]string, 0)

	if mask.isEmpty() {
		return
	}

	for i, bitmask := range mask.fds_bits {
		for j := uint32(0); j < NDPI_BITS; j++ {
			mask := uint32(i)*NDPI_BITS + j
			if bitmask&(1<<j) != 0 {
				for name, idp := range NdpiSate.Protocols.Supported {
					if mask == idp {
						dpi.Protocols = append(dpi.Protocols, name)
					}
				}
			}
		}
	}
}

func (dpi *Ndpi) protocolsToBitmask() (ret ndpiProtoBitmask, err error) {
	for _, prEl := range dpi.Protocols {
		if prEl == "all" {
			for name, v := range NdpiSate.Protocols.Supported {
				if !strings.HasPrefix(name, "badproto_") {
					ret.addProtocol(v)
				}
			}
			continue
		}
		doAdd := true
		if strings.HasPrefix(prEl, "-") {
			doAdd = false
			prEl = prEl[1:]
		}
		idp, found := NdpiSate.Protocols.Supported[prEl]
		if doAdd {
			if NdpiSate.Protocols.Disabled[prEl] {
				return ret, fmt.Errorf("disabled protoсol '%s'", prEl)
			}
			if !found {
				return ret, fmt.Errorf("unsupported protoсol '%s'", prEl)
			}
			ret.addProtocol(idp)
		} else if found {
			ret.delProtocol(idp)
		}
	}
	return ret, err
}

func (e *Ndpi) marshal(fam byte) ([]byte, error) {

	var attrs []netlink.Attribute

	if e.Key&NFTNL_EXPR_NDPI_HOSTNAME != 0 {
		attrs = append(attrs, netlink.Attribute{
			Type: NFTA_NDPI_HOSTNAME,
			Data: []byte(e.Hostname),
		})
		if len(e.Hostname) > 1 && e.Hostname[0] == '/' && e.Hostname[len(e.Hostname)-1] == '/' {
			_, err := regexp.Compile(e.Hostname)
			if err != nil {
				return nil, fmt.Errorf("Incorrect regular expression: %v", err)
			}
			e.NdpiFlags |= NFT_NDPI_FLAG_RE
		}
		e.NdpiFlags |= NFT_NDPI_FLAG_HOST
	}

	if (e.Key&NFTNL_EXPR_NDPI_FLAGS != 0) || e.NdpiFlags != 0 {
		attrs = append(attrs, netlink.Attribute{
			Type: NFTA_NDPI_FLAGS,
			Data: binaryutil.BigEndian.PutUint16(e.NdpiFlags),
		})
	}

	if e.Key&NFTNL_EXPR_NDPI_PROTO != 0 {
		mask, err := e.protocolsToBitmask()
		if err != nil {
			return nil, err
		}
		if !mask.isEmpty() {
			byteArray := make([]byte, len(mask.fds_bits)*4)
			for i, num := range mask.fds_bits {
				binary.LittleEndian.PutUint32(byteArray[i*4:], uint32(num))
			}
			attrs = append(attrs, netlink.Attribute{
				Type: NFTA_NDPI_PROTO,
				Data: byteArray[:],
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
			e.Hostname = string(data[:len(data)-1])
		case NFTA_NDPI_PROTO:
			var mask ndpiProtoBitmask
			for i := 0; i < len(data)/4; i++ {
				mask.fds_bits[i] = ndpiMaskType(binaryutil.BigEndian.Uint32(data[i*4:]))
			}
			e.bitmaskToProtocols(mask)
		}
	}
	return ad.Err()
}

type ndpiModuleState struct {
	FailReason error
	Protocols  struct {
		Supported map[string]ndpiMaskType
		Disabled  map[string]bool
	}
}

type ndpiModuleLoader = func(*bufio.Scanner) ndpiModuleState

var (
	// NdpiModuleProtocolsFile -
	NdpiModuleProtocolsFile = "/proc/net/xt_ndpi/proto"

	// NdpiSate -
	NdpiSate = ndpiLoadInternal()

	reVerDetect = regexp.MustCompile(`#id.*#version\s+([^\s]+)`)

	ndpiModuleLoaders = map[string]ndpiModuleLoader{
		NDPI_GIT_RELEASE: mod_4_3_0_8_6ae5394_Loader,
	}
)

func mod_4_3_0_8_6ae5394_Loader(r *bufio.Scanner) (ret ndpiModuleState) {
	reParser := regexp.MustCompile(
		`^([\da-f]+)\s+((?:[\da-f]+/[\da-f]+)|disabled)\s+([^\s#]+)`,
	)
	ret.Protocols.Supported = make(map[string]ndpiMaskType)
	ret.Protocols.Disabled = make(map[string]bool)

	for r.Scan() {
		li := r.Text()
		ss := reParser.FindStringSubmatch(li)

		if len(ss) == 4 {

			protoName := ss[3]
			protoMark := ss[2]
			protoId, err := strconv.ParseUint(ss[1], 16, 32)

			if err == nil {
				if protoMark != "disabled" {
					ret.Protocols.Supported[protoName] = ndpiMaskType(protoId)
				}
				ret.Protocols.Disabled[protoName] = (protoMark == "disabled")
			}
		}
	}

	return ret
}

func ndpiLoadInternal() (ret ndpiModuleState) {
	f, err := os.Open(NdpiModuleProtocolsFile)
	if err != nil {
		ret.FailReason = fmt.Errorf("opening xt_ndpi kernel module: %v", err)
		return ret
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var ver string

	for scanner.Scan() {
		line := scanner.Text()
		ss := reVerDetect.FindStringSubmatch(line)
		if len(ss) >= 2 {
			ver = ss[1]
			break
		}
	}

	if ver == "" {
		ret.FailReason = fmt.Errorf("no version detected")
		return ret
	}
	loader := ndpiModuleLoaders[ver]
	if loader == nil {
		ret.FailReason = fmt.Errorf("unsupported '%s' version detected", ver)
		return ret
	}
	return loader(scanner)
}
