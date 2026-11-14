package pathcoord

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"
)

// Poll does bounded state maintenance: refresh every pair and prune stale state.
// Pairs are created on-demand by REQUEST handlers, not by periodic admission.
func (o *Owner) Poll(ctx context.Context) (err error) {
	changed := make(map[string]map[string]struct{})
	o.mu.Lock()
	defer func() {
		o.mu.Unlock()
		if o.config.OnRuntimeUpdate != nil {
			for network, members := range changed {
				o.config.OnRuntimeUpdate(network, members)
			}
		}
	}()
	if err := o.check(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	now := o.config.Now()
	var failures []error
	for pair := range o.pairs {
		before, _ := o.coordinator.Snapshot(pair)
		_, _, err := o.refresh(pair, now)
		if err != nil && !definitiveRevocation(err) {
			failures = append(failures, err)
		}
		// A transient source read failure is not a changed projection. Read
		// retained state again so it cannot cause a push on every maintenance tick.
		after, _ := o.coordinator.Snapshot(pair)
		if !reflect.DeepEqual(before, after) {
			if changed[pair.NetworkID] == nil {
				changed[pair.NetworkID] = make(map[string]struct{})
			}
			changed[pair.NetworkID][pair.MemberAID] = struct{}{}
			changed[pair.NetworkID][pair.MemberBID] = struct{}{}
		}
	}
	o.prune()
	return errors.Join(failures...)
}

// Run owns one ticker and never overlaps Polls. A stopped owner cannot restart:
// construct a new owner/registry/authority epoch and reconcile retained clients.
func (o *Owner) Run(ctx context.Context) error {
	o.mu.Lock()
	if err := o.check(); err != nil {
		o.mu.Unlock()
		return err
	}
	if o.running {
		o.mu.Unlock()
		return fmt.Errorf("WG owner already running")
	}
	o.running = true
	o.mu.Unlock()
	defer o.Stop()
	ticker := time.NewTicker(o.config.TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-o.ctx.Done():
			return ErrOwnerStopped
		case <-ticker.C:
			_ = o.Poll(ctx)
		}
	}
}

func (o *Owner) Stop() {
	// Cancel before waiting for the gate, so a context-aware caller exits.
	o.stopped.Store(true)
	o.cancel()
	o.mu.Lock()
	defer o.mu.Unlock()
	for pair := range o.pairs {
		_ = o.remove(pair, "owner stopped", o.config.Now())
	}
	o.registry.mu.Lock()
	o.registry.runtimes = make(map[runtimeKey]*runtimeRecord)
	o.registry.mu.Unlock()
}
