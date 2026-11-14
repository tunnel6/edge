package pathcoord

import (
	"errors"
	"fmt"
	"time"
)

func (o *Owner) remove(pair PairKey, reason string, now time.Time) error {
	if _, ok := o.pairs[pair]; !ok {
		return nil
	}
	if _, err := o.coordinator.Cancel(pair, reason, now); err != nil {
		// Revision exhaustion must not leave an old authority dispatchable if
		// a revoked source later becomes readable again. A new owner is needed.
		o.stopped.Store(true)
		o.cancel()
		return err
	}
	if err := o.coordinator.Forget(pair); err != nil {
		return err
	}
	delete(o.pairs, pair)
	return nil
}

func (o *Owner) refresh(pair PairKey, now time.Time) (Scope, Snapshot, error) {
	scope, err := o.registry.Scope(pair)
	if err != nil {
		if definitiveRevocation(err) {
			_ = o.remove(pair, err.Error(), now)
		}
		return Scope{}, Snapshot{}, err
	}
	if o.pairs[pair] == nil {
		return Scope{}, Snapshot{}, fmt.Errorf("WG pair is not owned")
	}
	if _, err := o.coordinator.Synchronize(scope, now); err != nil {
		return Scope{}, Snapshot{}, err
	}
	snapshot, err := o.coordinator.Tick(scope, now)
	return scope, snapshot, err
}

func (o *Owner) prune() {
	o.registry.Prune()
}

// UpdateRegistry serializes a short real membership/policy mutation with owner
// operations/dispatch, then invalidates affected commands. The callback must not
// reenter Owner or perform network I/O. Even partial failed writes are refreshed.
// Real managers use this through their explicitly constructed PathOwner binding;
// callbacks must call private mutation bodies, never reenter gated public writes.
func (o *Owner) UpdateRegistry(change func() error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.check(); err != nil {
		return err
	}
	if change == nil {
		return fmt.Errorf("missing WG registry mutation")
	}
	err := change()
	var failures []error
	if err != nil {
		failures = append(failures, err)
	}
	for pair := range o.pairs {
		if _, _, err := o.refresh(pair, o.config.Now()); err != nil && !definitiveRevocation(err) {
			failures = append(failures, err)
		}
	}
	o.prune()
	return errors.Join(failures...)
}

func (o *Owner) Cancel(pair PairKey, reason string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.check(); err != nil {
		return err
	}
	return o.remove(pair, reason, o.config.Now())
}
