package dns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/H-BF/corlib/pkg/parallel"
	"github.com/ahmetb/go-linq/v3"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func Test_nsList(t *testing.T) {
	var x queryHelper
	x.nameservers = append(x.nameservers, "s1", "S1", " [S2] ", "s2", "  ")
	var r []string
	linq.From(x.nsList()).
		Select(func(i any) any {
			return strings.ToLower(i.(string))
		}).
		Sort(func(i, j interface{}) bool {
			return strings.Compare(i.(string), j.(string)) < 0
		}).ToSlice(&r)
	require.Equal(t, []string{"s1", "s2"}, r)
}

func Test_QueryA(t *testing.T) {
	mkA := func(ip string) *dns.A {
		return &dns.A{
			Hdr: dns.RR_Header{
				Ttl:    uint32(100),
				Class:  dns.ClassINET,
				Rrtype: dns.TypeA,
			},
			A: net.ParseIP(ip),
		}
	}
	cache := map[string]*dns.A{
		"domain1.org": mkA("1.1.1.1"),
		"domain2.org": mkA("1.1.1.2"),
		"domain3.org": mkA("1.1.1.3"),
		"domain4.org": mkA("1.1.1.4"),
		"domain5.org": mkA(""),
	}

	started := make(chan struct{})
	failed := make(chan struct{})
	srvDNS := &dns.Server{
		Net:  "tcp",
		Addr: ":100",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
			resp := &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:       m.Id,
					Response: true,
					Rcode:    dns.RcodeSuccess,
				},
			}
			for _, q := range m.Question {
				dn := strings.TrimRight(q.Name, ".")
				if rr := cache[dn]; rr != nil {
					x := *rr
					x.Hdr.Name = q.Name
					resp.Answer = append(resp.Answer, &x)
				}
			}
			if len(resp.Answer) == 0 && len(m.Question) > 0 {
				resp.Rcode = dns.RcodeNameError
			}
			_ = w.WriteMsg(resp)
		}),
		NotifyStartedFunc: func() {
			close(started)
		},
	}
	go func() {
		if e := srvDNS.ListenAndServe(); e != nil {
			close(failed)
		}
	}()
	select {
	case <-started:
		defer srvDNS.Shutdown() //nolint:errcheck
	case <-failed:
		t.FailNow()
		return
	}

	ctx := context.TODO()
	var domains []string
	linq.From(cache).
		Select(func(i any) any {
			return i.(linq.KeyValue).Key
		}).ToSlice(&domains)

	ans := make([]AddrAnswer, len(domains))
	nsAddr := srvDNS.Listener.Addr().(*net.TCPAddr)

	_ = parallel.ExecAbstract(len(domains), 10, func(i int) error {
		ans[i] = QueryA.Ask(ctx, domains[i],
			//WithDialDuration(time.Hour),
			WithReadDuration(time.Second),
			WithWriteDuration(time.Second),
			UsePort(nsAddr.Port),
			UseTCP{},
			WithNameservers{nsAddr.IP.String()},
			NoDefNS{},
		)
		return nil
	})
	linq.From(ans).
		ForEach(func(i any) {
			r := i.(AddrAnswer)
			require.NoErrorf(t, r.Error, "d(%s)", r.Domain)
			if a := cache[r.Domain]; a != nil {
				require.NotEmptyf(t, r.Addresses, "d(%s)", r.Domain)
				require.Equalf(t, r.Addresses[0].IP.String(), a.A.String(), "d(%s)", r.Domain)
			} else {
				require.Emptyf(t, r.Addresses, "d(%s)", r.Domain)
			}
		})
}

/*//
func Test_ID(t *testing.T) {
	ca := make(chan uint16, ^uint16(0))
	//n := ^uint16(0)
	for i := uint16(1); i > 0; i++ {
		ca <- i
	}
	fmt.Println(<-ca)
	fmt.Println(<-ca)
	fmt.Println(<-ca)

	var d net.Dialer
	//d.DialContext()
	_ = d
}
*/
