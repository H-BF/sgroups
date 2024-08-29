package jobs

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/H-BF/sgroups/internal/app/agent"
	"github.com/H-BF/sgroups/internal/app/agent/nft"
	"github.com/H-BF/sgroups/internal/app/agent/nft/resources"
	model "github.com/H-BF/sgroups/internal/domains/sgroups"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/host"
	"github.com/H-BF/corlib/pkg/patterns/observer"
	"github.com/H-BF/corlib/pkg/queue"
	"github.com/c-robinson/iplib"
	"github.com/pkg/errors"
)

func NewNftApplierJob(proc nft.NfTablesProcessor, client agent.SGClient, opts ...Option) *NftApplierJob {
	ret := &NftApplierJob{
		nftProcessor: proc,
		client:       client,
		que:          queue.NewFIFO[DomainAddresses](),
	}
	ret.trigger2apply.sgn = make(chan struct{}, 1)
	for _, o := range opts {
		switch t := o.(type) {
		case WithSubject:
			ret.Subject = t.Subject
		case WithNetNS:
			ret.netNS = string(t)
		}
	}
	if ret.Subject == nil {
		ret.Subject = observer.NewSubject()
	}
	return ret
}

// NftApplierJob -
type NftApplierJob struct {
	Subject       observer.Subject
	netNS         string
	client        agent.SGClient
	nftProcessor  nft.NfTablesProcessor
	que           queue.FIFO[DomainAddresses]
	stopped       chan struct{}
	onceRun       sync.Once
	onceClose     sync.Once
	appliedCount  int
	trigger2apply struct {
		sync.Mutex
		sgn            chan struct{}
		dbSyncChanged  int
		netConfChanged int
		syncStatus     *model.SyncStatus
		netConf        *host.NetConf
	}
}

// MakeObserver -
func (jb *NftApplierJob) MakeObserver() observer.Observer {
	return observer.NewObserver(
		jb.incomingEvents,
		false,
		agent.NetlinkUpdates{},
		agent.SyncStatusValue{},
		DomainAddresses{},
	)
}

// Close -
func (jb *NftApplierJob) Close() error {
	jb.onceClose.Do(func() {
		_ = jb.que.Close()
		jb.onceRun.Do(func() {})
		if jb.stopped != nil {
			<-jb.stopped
		}
	})
	return nil
}

// Run -
func (jb *NftApplierJob) Run(ctx context.Context) (err error) {
	const job = "nft-applier"

	var neverRun bool
	jb.onceRun.Do(func() {
		neverRun = true
		jb.stopped = make(chan struct{})
	})
	if !neverRun {
		return fmt.Errorf("%s: it has been run or closed yet", job)
	}

	log := logger.FromContext(ctx).Named(job)
	log.Info("start")
	defer func() {
		defer log.Info("stop")
		close(jb.stopped)
	}()
	for que := jb.que.Reader(); ; {
		select {
		case <-ctx.Done():
			log.Info("will exit cause it has canceled")
			return ctx.Err()
		case <-jb.trigger2apply.sgn:
			tr := &jb.trigger2apply
			tr.Lock()
			if tr.netConfChanged == 1 {
				log.Info("net conf has changed")
				tr.netConfChanged++
			}
			if tr.dbSyncChanged == 1 {
				log.Info("ruleset repo has changed")
				tr.dbSyncChanged++
			}
			if tr.netConf == nil || tr.syncStatus == nil {
				tr.Unlock()
			} else {
				tr.dbSyncChanged, tr.netConfChanged = 0, 0
				tr.Unlock()
				err = jb.doApply(ctx)
			}
		case o, ok := <-que:
			if !ok {
				log.Info("will exit cause it has closed")
				return nil
			}
			err = jb.handleDomainAddressesEvent(ctx, o)
		}
		if err != nil {
			log.Error(err)
			return err
		}
	}
}

// incomingEvents -
func (jb *NftApplierJob) incomingEvents(ev observer.EventType) { //async recv
	switch o := ev.(type) {
	case agent.NetlinkUpdates:
		jb.handleNetlinkEvent(o)
	case agent.SyncStatusValue:
		jb.handleSyncStatus(o)
	case DomainAddresses:
		_ = jb.que.Put(o)
	}
}

func (jb *NftApplierJob) handleSyncStatus(ev agent.SyncStatusValue) { //sync recv
	tr := &jb.trigger2apply
	tr.Lock()
	defer tr.Unlock()
	if apply := tr.syncStatus == nil; !apply {
		apply = !ev.UpdatedAt.Equal(tr.syncStatus.UpdatedAt)
		if !apply {
			return
		}
	}
	tr.syncStatus = &ev.SyncStatus
	tr.dbSyncChanged = 1
	select {
	case tr.sgn <- struct{}{}:
	default:
	}
}

func (jb *NftApplierJob) handleNetlinkEvent(ev agent.NetlinkUpdates) { //sync recv
	tr := &jb.trigger2apply
	tr.Lock()
	defer tr.Unlock()
	var cnf host.NetConf
	if tr.netConf != nil {
		cnf = tr.netConf.Clone()
	}
	updated := cnf.UpdFromWatcher(ev.Updates...)
	apply := tr.netConf == nil || updated
	tr.netConf = &cnf
	if apply {
		tr.netConfChanged = 1
		select {
		case tr.sgn <- struct{}{}:
		default:
		}
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
	jb.Subject.Notify(ev)
	return nil
}

func (jb *NftApplierJob) doApply(ctx context.Context) error {
	const maxLoadDuration = time.Minute

	log := logger.FromContext(ctx)
	localDataLoader := resources.LocalDataLoader{
		MaxLoadDiration: maxLoadDuration,
	}
	nc := *jb.trigger2apply.netConf
	localData, err := localDataLoader.Load(ctx, jb.client, nc)
	if err != nil {
		return err
	}
	log.Debug("local data are loaded")
	doApply := true
	if data := nft.LastAppliedRules(jb.netNS); data != nil {
		doApply = !data.LocalData.IsEq(localData)
		if !doApply {
			log.Debug("local data did not change since last load; new rules will not generate")
		}
	}

	fqdnStrategy := agent.FqdnStrategy.MustValue(ctx)
	if doApply {
		localData.ResolvedFQDN = new(resources.ResolvedFQDN)
		if fqdnStrategy.Eq(agent.FqdnRulesStartegyDNS) && localData.SG2FQDNRules.FQDNs.Len() > 0 {
			resolver := agent.GetDnsResolver()
			log.Debug("resolve FQDN(s)")
			localData.ResolvedFQDN.Resolve(ctx, localData.SG2FQDNRules, resolver)
		}
		var appliedRules nft.AppliedRules
		if appliedRules, err = jb.nftProcessor.ApplyConf(ctx, localData); err != nil {
			return err
		}
		nft.LastAppliedRulesUpd(jb.netNS, &appliedRules)
		ev := AppliedConfEvent{
			NetConf:      nc,
			AppliedRules: appliedRules,
		}
		jb.Subject.Notify(ev)
		jb.appliedCount++
	}
	if fqdnStrategy.Eq(agent.FqdnRulesStartegyDNS) {
		applied := nft.LastAppliedRules(jb.netNS)
		jb.enqueFQDNs(applied)
	}
	return nil
}

func (jb *NftApplierJob) enqueFQDNs(applied *nft.AppliedRules) {
	if applied == nil {
		return
	}
	reqs := make([]observer.EventType, 0,
		applied.LocalData.ResolvedFQDN.A.Len()+
			applied.LocalData.ResolvedFQDN.AAAA.Len())

	sources := sli(applied.LocalData.ResolvedFQDN.A,
		applied.LocalData.ResolvedFQDN.AAAA)
	for i, ipV := range sli(iplib.IP4Version, iplib.IP6Version) {
		sources[i].Iterate(func(domain model.FQDN, addr agent.DomainAddresses) bool {
			ev := Ask2ResolveDomainAddresses{
				IpVersion:   ipV,
				FQDN:        domain,
				ValidBefore: addr.At.Add(addr.TTL),
			}
			reqs = append(reqs, ev)
			return true
		})
	}
	jb.Subject.Notify(reqs...)
}

func sli[T any](args ...T) []T {
	return args
}
