package jobs

import (
	"context"

	"github.com/H-BF/sgroups/cmd/to-nft/internal"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/host"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft"
	"github.com/H-BF/sgroups/cmd/to-nft/internal/nft/cases"
	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/internal/queue"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/c-robinson/iplib"
	"github.com/pkg/errors"
)

func NewNftApplierJob(proc nft.NfTablesProcessor, client internal.SGClient, opts ...Option) *NftApplierJob {
	ret := &NftApplierJob{
		nftProcessor: proc,
		client:       client,
		agentSubject: internal.AgentSubject(),
		que:          queue.NewFIFO(),
	}
	for _, o := range opts {
		switch t := o.(type) {
		case WithAgentSubject:
			ret.agentSubject = t.Subject
		case WithDnsResolver:
			ret.dnsResolver = t.DnsRes
		case WithNetNS:
			ret.netNS = string(t)
		}
	}
	ret.Observer = observer.NewObserver(
		ret.incomingEvents,
		false,
		applyConfigEvent{},
		internal.NetlinkUpdates{},
		internal.SyncStatusValue{},
		DomainAddresses{},
	)
	ret.agentSubject.ObserversAttach(ret)
	return ret
}

// NftApplierJob -
type NftApplierJob struct {
	observer.Observer
	netNS        string
	client       internal.SGClient
	nftProcessor nft.NfTablesProcessor
	agentSubject observer.Subject
	dnsResolver  internal.DomainAddressQuerier
	que          *queue.FIFO
	syncStatus   *model.SyncStatus
	netConf      *host.NetConf
}

type applyConfigEvent struct {
	observer.TextMessageEvent
}

// Close -
func (jb *NftApplierJob) Close() error {
	jb.agentSubject.ObserversDetach(jb)
	_ = jb.Observer.Close()
	_ = jb.que.Close()
	return nil
}

// Run -
func (jb *NftApplierJob) Run(ctx context.Context) error {
	que := jb.que.Reader()
	for {
		var raw any
		select {
		case raw = <-que:
		case <-ctx.Done():
			return ctx.Err()
		}
		switch o := raw.(type) {
		case internal.SyncStatusValue:
			jb.handleSyncStatus(ctx, o)
		case internal.NetlinkUpdates:
			jb.handleNetlinkEvent(ctx, o)
		case applyConfigEvent:
			logger.Info(ctx, o)
			if err := jb.doApply(ctx); err != nil {
				return err
			}
		case DomainAddresses:
			appliedRules := nft.LastAppliedRules(jb.netNS)
			if appliedRules == nil {
				break
			}
			if o.DnsAnswer.Err == nil {
				p := nft.UpdateFqdnNetsets{
					IPVersion: o.IpVersion,
					TTL:       o.DnsAnswer.TTL,
					FQDN:      o.FQDN,
					Addresses: o.DnsAnswer.IPs,
				}
				if err := nft.PatchAppliedRules(ctx, appliedRules, p); err != nil {
					if errors.Is(err, nft.ErrPatchNotApplicable) {
						break
					}
					return err
				}
			}
			ev := Ask2ResolveDomainAddresses{
				IpVersion: o.IpVersion,
				FQDN:      o.FQDN,
				TTL:       o.DnsAnswer.TTL,
			}
			jb.agentSubject.Notify(ev)
		}
	}
}

func (jb *NftApplierJob) incomingEvents(ev observer.EventType) { //async recv
	_ = jb.que.Put(ev)
}

func (jb *NftApplierJob) handleSyncStatus(_ context.Context, ev internal.SyncStatusValue) { //sync recv
	if apply := jb.syncStatus == nil; !apply {
		apply = ev.UpdatedAt.After(jb.syncStatus.UpdatedAt)
		if !apply {
			return
		}
	}
	jb.syncStatus = &ev.SyncStatus
	jb.agentSubject.Notify(applyConfigEvent{
		TextMessageEvent: observer.NewTextEvent("rulesets repo has changed"),
	})
}

func (jb *NftApplierJob) handleNetlinkEvent(_ context.Context, ev internal.NetlinkUpdates) { //sync recv
	var cnf host.NetConf
	if jb.netConf != nil {
		cnf = jb.netConf.Clone()
	}
	cnf.UpdFromWatcher(ev.Updates...)
	if apply := jb.netConf == nil; !apply {
		apply = !jb.netConf.IPAdresses.Eq(cnf.IPAdresses)
		if !apply {
			return
		}
	}
	jb.netConf = &cnf
	jb.agentSubject.Notify(applyConfigEvent{
		TextMessageEvent: observer.NewTextEvent("net conf has changed"),
	})
}

func (jb *NftApplierJob) doApply(ctx context.Context) error {
	if jb.netConf == nil || jb.syncStatus == nil {
		return nil
	}

	log := logger.FromContext(ctx)
	localDataLoader := cases.LocalDataLoader{
		Logger: log,
		DnsRes: jb.dnsResolver,
	}

	localData, err := localDataLoader.Load(ctx, jb.client, *jb.netConf)
	if err != nil {
		return err
	}
	log.Debug("local data are loaded")
	if data := nft.LastAppliedRules(jb.netNS); data != nil {
		eq := data.LocalData.IsEq(localData)
		if eq {
			log.Debug("local data did not change since last load; new rules will not geneate")
			return nil
		}
	}

	var appliedRules nft.AppliedRules
	if appliedRules, err = jb.nftProcessor.ApplyConf(ctx, localData); err != nil {
		return err
	}
	nft.LastAppliedRulesUpd(jb.netNS, &appliedRules)
	ev := AppliedConfEvent{
		NetConf:      jb.netConf.Clone(),
		AppliedRules: appliedRules,
	}
	jb.agentSubject.Notify(ev)

	reqs := make([]observer.EventType, 0,
		appliedRules.LocalData.SG2FQDNRules.Resolved.A.Len()+
			appliedRules.LocalData.SG2FQDNRules.Resolved.AAAA.Len())

	sources := sli(appliedRules.LocalData.SG2FQDNRules.Resolved.A,
		appliedRules.LocalData.SG2FQDNRules.Resolved.AAAA)
	for i, ipV := range sli(iplib.IP4Version, iplib.IP6Version) {
		sources[i].Iterate(func(domain model.FQDN, addr internal.DomainAddresses) bool {
			ev := Ask2ResolveDomainAddresses{
				IpVersion: ipV,
				FQDN:      domain,
				TTL:       addr.TTL,
			}
			reqs = append(reqs, ev)
			return true
		})
	}
	jb.agentSubject.Notify(reqs...)
	return nil
}

func sli[T any](args ...T) []T {
	return args
}
