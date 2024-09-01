package nft

import (
	"context"
	"time"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/backoff"
	"github.com/pkg/errors"
)

// PatchAppliedRules -
func PatchAppliedRules(ctx context.Context, rules *AppliedRules, p Patch) (err error) {
	log := logger.FromContext(ctx).Named("nft.patch")
	if len(rules.NetNS) > 0 {
		log = log.WithField("net-ns", rules.NetNS)
	}
	defer func() {
		if err == nil {
			log.Infof("%s is applied", p)
		} else {
			tern(errors.Is(err, ErrPatchNotApplicable),
				log.Warnf, log.Errorf)("%v", err)
		}
	}()

	for bk := MakeBatchBackoff(); ; {
		err = p.Apply(ctx, rules)
		if err == nil || errors.Is(err, ErrPatchNotApplicable) {
			break
		}
		pauseDuration := bk.NextBackOff()
		if pauseDuration == backoff.Stop {
			break
		}
		log.Errorf("%s has failed: %v; will retry after %v",
			p, err, pauseDuration)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pauseDuration):
		}
	}
	return err
}
