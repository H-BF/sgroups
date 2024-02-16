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
func (jb *NftApplierJob) Run(ctx context.Context) (err error) {
	log := logger.FromContext(ctx).Named("nft-applier-proc")
	log.Info("start")
	defer log.Info("stop")
	for que := jb.que.Reader(); ; {
		select {
		case <-ctx.Done():
			log.Info("will exit cause it has canceled")
			return ctx.Err()
		case raw, ok := <-que:
			if !ok {
				log.Info("will exit cause it has closed")
				return nil
			}
			switch o := raw.(type) {
			case internal.SyncStatusValue:
				jb.handleSyncStatus(ctx, o)
			case internal.NetlinkUpdates:
				jb.handleNetlinkEvent(ctx, o)
			case applyConfigEvent:
				logger.Info(ctx, o)
				err = jb.doApply(ctx)
			case DomainAddresses:
				err = jb.handleDomainAddressesEvent(ctx, o)
			}
			if err != nil {
				log.Error(err)
				return err
			}
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
	apply := jb.netConf == nil
	if !apply {
		apply = !jb.netConf.IPAdresses.Eq(cnf.IPAdresses)
	}
	jb.netConf = &cnf
	if apply {
		jb.agentSubject.Notify(applyConfigEvent{
			TextMessageEvent: observer.NewTextEvent("net conf has changed"),
		})
	}
}

func (jb *NftApplierJob) handleDomainAddressesEvent(ctx context.Context, o DomainAddresses) error {
	appliedRules := nft.LastAppliedRules(jb.netNS)
	if appliedRules == nil {
		return nil
	}
	ev := Ask2ResolveDomainAddresses{
		IpVersion: o.IpVersion,
		FQDN:      o.FQDN,
	}
	if o.DnsAnswer.Err == nil {
		ev.ValidBefore = o.DnsAnswer.At.Add(o.DnsAnswer.TTL)
		p := nft.UpdateFqdnNetsets{
			IPVersion: o.IpVersion,
			FQDN:      o.FQDN,
			Addresses: o.DnsAnswer.IPs,
		}
		if err := nft.PatchAppliedRules(ctx, appliedRules, p); err != nil {
			if errors.Is(err, nft.ErrPatchNotApplicable) {
				return nil
			}
			return err
		}
	}
	jb.agentSubject.Notify(ev)
	return nil
}

func (jb *NftApplierJob) doApply(ctx context.Context) error {
	if jb.netConf == nil || jb.syncStatus == nil {
		return nil
	}

	log := logger.FromContext(ctx)
	localDataLoader := cases.LocalDataLoader{
		Logger: log,
		DnsRes: internal.GetDnsResolver(),
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

	fqdnStrategy := internal.FqdnStrategy.MustValue(ctx)
	if !fqdnStrategy.Eq(internal.FqdnRulesStartegyNDPI) {
		localData.ResolvedFQDN = new(cases.ResolvedFQDN)
		if localData.SG2FQDNRules.FQDNs.Len() > 0 {
			resolver := internal.GetDnsResolver()
			log.Debug("resolve FQDN(s)")
			localData.ResolvedFQDN.Resolve(ctx, localData.SG2FQDNRules, resolver)
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

	if !fqdnStrategy.Eq(internal.FqdnRulesStartegyNDPI) {
		reqs := make([]observer.EventType, 0,
			appliedRules.LocalData.ResolvedFQDN.A.Len()+
				appliedRules.LocalData.ResolvedFQDN.AAAA.Len())

		sources := sli(appliedRules.LocalData.ResolvedFQDN.A,
			appliedRules.LocalData.ResolvedFQDN.AAAA)
		for i, ipV := range sli(iplib.IP4Version, iplib.IP6Version) {
			sources[i].Iterate(func(domain model.FQDN, addr internal.DomainAddresses) bool {
				ev := Ask2ResolveDomainAddresses{
					IpVersion:   ipV,
					FQDN:        domain,
					ValidBefore: addr.At.Add(addr.TTL),
				}
				reqs = append(reqs, ev)
				return true
			})
		}
		jb.agentSubject.Notify(reqs...)
	}
	return nil
}

func sli[T any](args ...T) []T {
	return args
}
