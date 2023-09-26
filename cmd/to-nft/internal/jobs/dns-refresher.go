package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/internal/dict"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/internal/queue"

	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/c-robinson/iplib"
)

type (

	// Ask2PatchDomainAddresses -
	Ask2PatchDomainAddresses struct {
		IpVersion int
		FQDN      model.FQDN
		TTL       time.Duration

		observer.EventType
	}

	// DomainAddressesPatch -
	DomainAddressesPatch struct {
		IpVersion int
		FQDN      model.FQDN
		DnsAnswer internal.DomainAddresses
		At        time.Time

		observer.EventType
	}

	fqdn2timer = dict.RBDict[Ask2PatchDomainAddresses, *time.Timer]

	// FqdnRefresher -
	FqdnRefresher struct {
		AgentSubj observer.Subject
		Resolver  internal.DomainAddressQuerier
	}
)

func (rf *FqdnRefresher) Run(ctx context.Context) {
	var activeQueries fqdn2timer
	defer activeQueries.Iterate(func(_ Ask2PatchDomainAddresses, v *time.Timer) bool {
		_ = v.Stop()
		return true
	})
	que := queue.NewFIFO()
	defer que.Close()
	obs := observer.NewObserver(func(ev observer.EventType) {
		_ = que.Put(ev)
	}, false, Ask2PatchDomainAddresses{})
	defer rf.AgentSubj.ObserversDetach(obs)
	rf.AgentSubj.ObserversAttach(obs)
	for events := que.Reader(); ; {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-events:
			if !ok {
				return
			}
			switch ev := raw.(type) {
			case DomainAddressesPatch:
				rf.AgentSubj.Notify(ev)
			case Ask2PatchDomainAddresses:
				if activeQueries.At(ev) != nil {
					return
				}
				ttl := ev.TTL
				if ttl < time.Minute {
					ttl = time.Minute
				}
				newTimer := time.AfterFunc(ttl, func() {
					defer activeQueries.Del(ev)
					ret := rf.resolve(ctx, ev)
					que.Put(ret)
				})
				activeQueries.Put(ev, newTimer)
			}
		}
	}
}

func (rf *FqdnRefresher) resolve(ctx context.Context, ask Ask2PatchDomainAddresses) DomainAddressesPatch {
	ret := DomainAddressesPatch{
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
func (a Ask2PatchDomainAddresses) Cmp(other Ask2PatchDomainAddresses) int {
	if a.IpVersion > other.IpVersion {
		return 1
	}
	if a.IpVersion < other.IpVersion {
		return -1
	}
	return a.FQDN.Cmp(other.FQDN)
}
