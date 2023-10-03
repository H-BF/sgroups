package dns

import (
	"net"
	"regexp"
	"strings"
	"syscall"
	"time"

	bkf "github.com/H-BF/corlib/pkg/backoff"
	"github.com/ahmetb/go-linq/v3"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

const (
	defaultResolvConf    = "/etc/resolv.conf"
	defaultPort          = uint16(53)
	defaultDialDuration  = 3 * time.Second
	defaultReadDuration  = 3 * time.Second
	defaultWriteDuration = 3 * time.Second
)

type queryHelper struct {
	useTCP        bool
	noDefNS       bool
	nameservers   []string
	port          uint16
	localAddr     string
	backoff       bkf.Backoff
	dialDuration  time.Duration
	readDuration  time.Duration
	writeDuration time.Duration
}

var reUnbrace = regexp.MustCompile(`(?:^\s*\[\s*([^\s\[\]]+)\s*\]\s*$)|(?:^\s*([^\s\[\]]*)\s*$)`)

func tern[T any](ok bool, a, b T) T {
	if ok {
		return a
	}
	return b
}

func (rs *queryHelper) init(opts ...Option) {
	rs.dialDuration = defaultDialDuration
	rs.writeDuration = defaultWriteDuration
	rs.readDuration = defaultReadDuration
	rs.port = defaultPort
	rs.backoff = &bkf.StopBackoff
	for _, o := range opts {
		o.apply(rs)
	}
	if !rs.noDefNS {
		conf, e := dns.ClientConfigFromFile(defaultResolvConf)
		if e == nil {
			rs.nameservers = append(rs.nameservers, conf.Servers...)
		}
	}
}

func (rs queryHelper) buildClient() (*dns.Client, error) {
	la, e := rs.getLocalAddress()
	if e != nil {
		return nil, e
	}
	c := &dns.Client{
		UDPSize:      dns.DefaultMsgSize,
		Net:          tern(rs.useTCP, "tcp", "udp"),
		DialTimeout:  rs.dialDuration,
		ReadTimeout:  rs.readDuration,
		WriteTimeout: rs.writeDuration,
		Dialer: &net.Dialer{
			LocalAddr: la,
			Timeout:   rs.dialDuration,
			Control: func(a, b string, raw syscall.RawConn) error {
				var opErr error
				e := raw.Control(func(fd uintptr) {
					opErr = syscall.SetsockoptInt(
						int(fd), syscall.SOL_SOCKET,
						unix.SO_REUSEPORT, 1)
				})
				return tern(e != nil, e, opErr)
			},
		},
	}
	return c, nil
}

func (rs queryHelper) getLocalAddress() (net.Addr, error) {
	var ret struct {
		net.Addr
		error
	}
	if s := strings.TrimSpace(rs.localAddr); s != "" {
		tern(rs.useTCP,
			func(s string) {
				ret.Addr, ret.error = net.ResolveTCPAddr("", s)
			},
			func(s string) {
				ret.Addr, ret.error = net.ResolveUDPAddr("", s)
			},
		)(s)
	}
	return ret.Addr, ret.error
}

func (rs queryHelper) makeMsq(q ...dns.Question) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
			Rcode:            dns.RcodeSuccess,
			Opcode:           dns.OpcodeQuery,
			Id:               dns.Id(),
		},
		Question: q,
	}
}

func (rs queryHelper) nsList() []string {
	ss := make([]string, 0, len(rs.nameservers))
	linq.From(rs.nameservers).
		Select(func(i any) any {
			return reUnbrace.FindStringSubmatch(i.(string))
		}).
		Where(func(i any) bool {
			return len(i.([]string)) > 2
		}).
		Select(func(i any) any {
			v := i.([]string)
			return tern(len(v[1]) > 0, v[1], v[2])
		}).
		Where(func(i any) bool {
			return len(i.(string)) > 0
		}).
		DistinctBy(func(i any) any {
			return strings.ToLower(i.(string))
		}).ToSlice(&ss)
	return ss
}
