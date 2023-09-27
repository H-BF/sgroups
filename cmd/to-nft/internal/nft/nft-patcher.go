package nft

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/backoff"
	nftlib "github.com/google/nftables"
	"github.com/pkg/errors"
)

// PatchAppliedRules -
func PatchAppliedRules(ctx context.Context, rules *AppliedRules, p Patch) (err error) {
	exec := knownPatchers[reflect.ValueOf(p).Type()]
	if exec.patcher == nil {
		panic(
			fmt.Errorf("unsupported PATCH type %#v", p),
		)
	}
	log := logger.FromContext(ctx).
		Named("nft").
		WithField("apply-patch", exec.name)
	if len(rules.NetNS) > 0 {
		log = log.WithField("net-NS", rules.NetNS)
	}
	log.Infof("begin")
	defer func() {
		if err != nil {
			log.Errorf("%v", err)
		}
	}()
	err = rules.Patch(p, func() error {
		bk := MakeBatchBackoff()
		for {
			e := exec.patcher(ctx, rules, p)
			if e == nil {
				log.Infof("done")
				return nil
			}
			if errors.Is(e, ErrPatchNotApplicable) {
				return e
			}
			pauseDuration := bk.NextBackOff()
			if pauseDuration == backoff.Stop {
				return e
			}
			log.Errorf("%v; will retry after %v",
				e, pauseDuration)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pauseDuration):
			}
		}
	})
	return err
}

type patcher = func(ctx context.Context, rules *AppliedRules, p Patch) error

func patch2UpdateFqdnNetsets(ctx context.Context, rules *AppliedRules, p Patch) error {
	tx, err := NewTx(rules.NetNS)
	if err != nil {
		return err
	}
	defer tx.Close()
	var nftConf NFTablesConf
	if err = nftConf.Load(tx.Conn); err != nil {
		return err
	}
	targetTable := NfTableKey{
		TableFamily: nftlib.TableFamilyINet,
		Name:        rules.TargetTable,
	}
	v := p.(UpdateFqdnNetsets)
	netSets := nftConf.Sets.At(targetTable)
	netsetName := nameUtils{}.
		nameOfFqdnNetSet(v.IPVersion, v.FQDN)
	set := netSets.At(netsetName)
	if set.Set == nil {
		return ErrPatchNotApplicable
	}
	elements := setsUtils{}.nets2SetElements(v.NetSet(), v.IPVersion)
	if err = tx.SetAddElements(set.Set, elements); err != nil {
		panic(err)
	}
	err = tx.FlushAndClose()
	if err == nil {
		_ = err
	}
	return err
}

var knownPatchers = map[reflect.Type]struct {
	patcher
	name string
}{
	reflect.ValueOf((*UpdateFqdnNetsets)(nil)).Type().Elem(): {
		patch2UpdateFqdnNetsets,
		"Update-FQDN-Netsets",
	},
}
