package jobs

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/internal/queue"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/jsonview"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/c-robinson/iplib"
)

type (

	// Ask2ResolveDomainAddresses -
	Ask2ResolveDomainAddresses struct {
		IpVersion int
		FQDN      model.FQDN
		TTL       time.Duration

		observer.EventType
	}

	// DomainAddresses -
	DomainAddresses struct {
		IpVersion int
		FQDN      model.FQDN
		DnsAnswer internal.DomainAddresses
		At        time.Time

		observer.EventType
	}

	// FqdnRefresher -
	FqdnRefresher struct {
		AgentSubj observer.Subject
		Resolver  internal.DomainAddressQuerier
	}
)

func (rf *FqdnRefresher) Run(ctx context.Context) {
	type fqdn2timer = struct {
		sync.Mutex
		dict.RBDict[Ask2ResolveDomainAddresses, *time.Timer]
	}
	var activeQueries fqdn2timer
	defer activeQueries.Iterate(func(_ Ask2ResolveDomainAddresses, v *time.Timer) bool {
		_ = v.Stop()
		return true
	})
	que := queue.NewFIFO()
	defer que.Close()
	obs := observer.NewObserver(func(ev observer.EventType) {
		_ = que.Put(ev)
	}, false, Ask2ResolveDomainAddresses{})
	defer rf.AgentSubj.ObserversDetach(obs)
	rf.AgentSubj.ObserversAttach(obs)

	log := logger.FromContext(ctx).Named("dns")
	log.Info("start")
	defer log.Info("stop")
	for events := que.Reader(); ; {
		select {
		case <-ctx.Done():
			log.Info("will exit cause parent context has canceled")
			return
		case raw, ok := <-events:
			if !ok {
				log.Infof("will exit cause it has closed")
				return
			}
			switch ev := raw.(type) {
			case DomainAddresses:
				log1 := log.WithField("domain", ev.FQDN).WithField("ip-v", ev.IpVersion)
				if e := ev.DnsAnswer.Err; e != nil {
					log1.Error(e)
				} else {
					log1.Debug("resolved")
				}
				rf.AgentSubj.Notify(ev)
			case Ask2ResolveDomainAddresses:
				activeQueries.Lock()
				if activeQueries.At(ev) == nil {
					ttl := ev.TTL
					if ttl < time.Minute {
						ttl = time.Minute
					}
					log.Debugw("ask-to-resolve",
						"ip-v", ev.IpVersion,
						"domain", ev.FQDN.String(),
						"after", jsonview.Stringer(ttl),
					)
					newTimer := time.AfterFunc(ttl, func() {
						activeQueries.Lock()
						activeQueries.Del(ev)
						activeQueries.Unlock()
						ret := rf.resolve(ctx, ev)
						que.Put(ret)
					})
					activeQueries.Put(ev, newTimer)
				}
				activeQueries.Unlock()
			}
		}
	}
}

func (rf *FqdnRefresher) resolve(ctx context.Context, ask Ask2ResolveDomainAddresses) DomainAddresses {
	ret := DomainAddresses{
		IpVersion: ask.IpVersion,
		FQDN:      ask.FQDN,
	}
	domain := ask.FQDN.String()
	switch ask.IpVersion {
	case iplib.IP4Version:
		ret.DnsAnswer = rf.Resolver.A(ctx, domain)
	case iplib.IP6Version:
		ret.DnsAnswer = rf.Resolver.AAAA(ctx, domain)
	default:
		panic(
			fmt.Errorf("FqdnRefresher: passed unsupported IP version: %v'", ask.IpVersion),
		)
	}
	ret.At = time.Now().Local()
	return ret
}

// Cmp -
func (a Ask2ResolveDomainAddresses) Cmp(other Ask2ResolveDomainAddresses) int {
	if a.IpVersion > other.IpVersion {
		return 1
	}
	if a.IpVersion < other.IpVersion {
		return -1
	}
	return a.FQDN.Cmp(other.FQDN)
}
