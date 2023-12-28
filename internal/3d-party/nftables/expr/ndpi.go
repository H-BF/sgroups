package expr

import (
	"encoding/binary"
	"io"
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
	//Number of bits to describe one chunk of protocols
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

// it itreates over nonzero bits
func (p *ndpiProtoBitmask) iterate(fn func(n int) bool) {
	for i, bitmask := range p.fds_bits {
		if bitmask == 0 {
			continue
		}

		for j := 0; j < int(NDPI_BITS); j++ {
			if ((1 << j) & bitmask) == 0 {
				continue
			}
			if !fn(i*int(NDPI_BITS) + j) {
				return
			}
		}
	}
}

const NDPI_PROTOCOL_UNKNOWN = 0

const (
	NFTA_NDPI_UNSPEC = iota
	NFTA_NDPI_PROTO
	NFTA_NDPI_FLAGS
	NFTA_NDPI_HOSTNAME
)

/*//TODO: Так я понял, до свободного творчества будем расти вместе по шагам
1 - убираем этот билдер
2 - пишем норм функцию NewNdpi c опциями см ниже
*/

type Ndpi struct {
	/*Additional flags to setup and observe different option for the NDPI.
	Range of values: 0x0 ... 0x3FFF
	Available flags to setup:
		NFT_NDPI_FLAG_INVERT 		= 0x01
		NFT_NDPI_FLAG_ERROR 		= 0x2
		NFT_NDPI_FLAG_M_PROTO		= 0x4
		NFT_NDPI_FLAG_P_PROTO		= 0x8
		NFT_NDPI_FLAG_HAVE_MASTER	= 0x10
		NFT_NDPI_FLAG_INPROGRESS	= 0x100
		NFT_NDPI_FLAG_JA3S			= 0x200
		NFT_NDPI_FLAG_JA3C			= 0x400
		NFT_NDPI_FLAG_TLSFP			= 0x800
		NFT_NDPI_FLAG_TLSV			= 0x1000
		NFT_NDPI_FLAG_UNTRACKED		= 0x2000
	*/
	NdpiFlags uint16 //TODO: rename  NdpiFlags --> Flags

	Protocols []string

	// Equivalent to expression flags.
	// Indicates that an option is set by setting a bit
	Key uint32

	Hostname string
}

type ndpiOpt interface {
	apply(*Ndpi)
}

type ndpiOptFunc func(*Ndpi)

// NewNdpi creates Ndpi expression properly
func NewNdpi(opts ...ndpiOpt) (res *Ndpi, err error) {
	res = new(Ndpi)
	for _, o := range opts {
		o.apply(res)
	}
	/*// TODO
	1 здесь в зависимости о установленных Hostname Protocols ожидаю что Flags и Key устаковят правильные биты
	2 если что-то установнено неправильно - значит - ошибка
	3 если модуль Ndpi не подгружет - ошика
	3 если есть конфликт модуля и переданных протоколов - ошибка
	*/
	return res, err
}

func (f ndpiOptFunc) apply(o *Ndpi) { //impl ndpiOpt
	f(o)
}

// ----НАПРИМЕР

// NdpiWithHost -
func NdpiWithHost(hosname string) ndpiOpt {
	return ndpiOptFunc(func(o *Ndpi) {
		o.Hostname = hosname
	})
}

// NdpiWithProtocols -
func NdpiWithProtocols(pp ...string) ndpiOpt {
	return ndpiOptFunc(func(o *Ndpi) {
		o.Protocols = append(o.Protocols, pp...)
	})
}

// +NdpiWithKeys +NdpiWithFlags

type NdpiBuilderI interface {
	SetHostname(val string) NdpiBuilderI
	SetProto(val []string) NdpiBuilderI
	SetNdpiFlags(val uint16) NdpiBuilderI
	SetKey(val uint32) NdpiBuilderI
	Build() Ndpi
}

type NdpiBuilder struct {
	ndpiFlags uint16

	protocols []string

	key uint32

	hostname string
}

func (b *NdpiBuilder) SetHostname(val string) NdpiBuilderI {
	b.hostname = val
	return b
}

func (b *NdpiBuilder) SetProto(val []string) NdpiBuilderI {
	b.protocols = val
	return b
}

func (b *NdpiBuilder) SetNdpiFlags(val uint16) NdpiBuilderI {
	b.ndpiFlags = val
	return b
}

func (b *NdpiBuilder) SetKey(val uint32) NdpiBuilderI {
	b.key = val
	return b
}

func (b *NdpiBuilder) Build() Ndpi {
	return Ndpi{
		Hostname:  b.hostname,
		Protocols: b.protocols,
		NdpiFlags: b.ndpiFlags,
		Key:       b.key,
	}
}

func NewNdpiBuilder() NdpiBuilderI {
	return &NdpiBuilder{}
}

func (dpi *Ndpi) poplulateProtocols(mask *ndpiProtoBitmask) {
	dpi.Protocols = nil
	mask.iterate(func(n int) bool {
		p := NdpiState.Protocols.numbit2ProtoName[n]
		if p != "" {
			dpi.Protocols = append(dpi.Protocols, p)
		}
		return true
	})
}

func (dpi *Ndpi) protocolsToBitmask() (ret ndpiProtoBitmask, err error) {
	for _, prEl := range dpi.Protocols {
		if prEl == "all" {
			for name, v := range NdpiState.Protocols.Supported {
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
		idp, found := NdpiState.Protocols.Supported[prEl]
		if doAdd {
			if NdpiState.Protocols.Disabled[prEl] {
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
	var mask ndpiProtoBitmask
	var err error

	if e.Hostname != "" {
		attrs = append(attrs, netlink.Attribute{
			Type: NFTA_NDPI_HOSTNAME,
			Data: []byte(e.Hostname),
		})
		if e.Hostname[0] == '/' && e.Hostname[len(e.Hostname)-1] == '/' {
			_, err = regexp.Compile(e.Hostname)
			if err != nil {
				return nil, fmt.Errorf("incorrect regular expression: %v", err)
			}
			e.NdpiFlags |= NFT_NDPI_FLAG_RE
		}
		e.NdpiFlags |= NFT_NDPI_FLAG_HOST
	}

	if len(e.Protocols) != 0 {
		mask, err = e.protocolsToBitmask()
		if err != nil {
			return nil, err
		}
		byteArray := make([]byte, len(mask.fds_bits)*4)
		for i, num := range mask.fds_bits {
			binary.LittleEndian.PutUint32(byteArray[i*4:], uint32(num))
		}
		attrs = append(attrs, netlink.Attribute{
			Type: NFTA_NDPI_PROTO,
			Data: byteArray[:],
		})
	}

	if mask.isEmpty() {
		e.NdpiFlags |= NFT_NDPI_FLAG_EMPTY
	}

	if (e.Key&NFTNL_EXPR_NDPI_FLAGS != 0) || e.NdpiFlags != 0 {
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
			e.Hostname = string(data[:len(data)-1])
		case NFTA_NDPI_PROTO:
			var mask ndpiProtoBitmask
			for i := 0; i < len(data)/4; i++ {
				mask.fds_bits[i] = ndpiMaskType(binaryutil.BigEndian.Uint32(data[i*4:]))
			}
			e.poplulateProtocols(&mask)
		}
	}
	return ad.Err()
}

type ndpiModuleState struct {
	FailReason error
	Protocols  struct {
		Supported        map[string]ndpiMaskType
		numbit2ProtoName [NDPI_NUM_BITS]string
		Disabled         map[string]bool
	}
}

type ndpiModuleLoader = func(io.Reader) ndpiModuleState

var (
	// NdpiModuleProtocolsFile - ndpi kernel file contains description for protocols
	NdpiModuleProtocolsFile = "/proc/net/xt_ndpi/proto"

	// NdpiState - structure contains lists of supported and disabled protocols
	NdpiState = ndpiLoadInternal()

	reVerDetect = regexp.MustCompile(`#id.*#version\s+([^\s]+)`)

	ndpiModuleLoaders = map[string]ndpiModuleLoader{
		NDPI_GIT_RELEASE: mod_4_3_0_8_6ae5394_Loader,
	}
)

func mod_4_3_0_8_6ae5394_Loader(r io.Reader) (ret ndpiModuleState) {
	reParser := regexp.MustCompile(
		`^([\da-f]+)\s+((?:[\da-f]+/[\da-f]+)|disabled)\s+([^\s#]+)`,
	)
	ret.Protocols.Supported = make(map[string]ndpiMaskType)
	ret.Protocols.Disabled = make(map[string]bool)

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		li := sc.Text()
		ss := reParser.FindStringSubmatch(li)
		if len(ss) == 4 {
			protoName := ss[3]
			protoMark := ss[2]
			protoId, err := strconv.ParseUint(ss[1], 16, 32)
			if err == nil {
				if protoMark != "disabled" {
					ret.Protocols.Supported[protoName] = ndpiMaskType(protoId)
					ret.Protocols.numbit2ProtoName[ndpiMaskType(protoId)] = protoName
				}
				ret.Protocols.Disabled[protoName] = (protoMark == "disabled")
			}
		}
	}

	return ret
}

func ndpiLoadInternal() (ret ndpiModuleState) {
	openModuleInfo := func() (io.ReadCloser, error) {
		f, err := os.Open(NdpiModuleProtocolsFile)
		if err != nil {
			err = fmt.Errorf("opening 'xt_ndpi' kernel module: %v", err)
		}
		return f, err
	}
	f, err := openModuleInfo()
	if err != nil {
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
	//Since we're reading from a kernel module we have to reopen the file
	//if a new read buffer will be created
	var f1 io.ReadCloser
	if f1, err = openModuleInfo(); err != nil {
		return ret
	}
	defer f1.Close()
	return loader(f1)
}
