package pathcoord

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
)

type OwnerConfig struct {
	// TransactionTimeout bounds the active negotiation gate. An unconfirmed
	// COMMIT is retained for recovery after this gate expires.
	TransactionTimeout time.Duration
	Budgets            Budgets
	Registry           RegistryLimits
	MaxPairs           int
	ControlBurst       int // maximum in-flight client switches per network/member, counting both participants
	TickInterval       time.Duration
	Now                func() time.Time // nil selects time.Now; injected clocks must be concurrency safe
	// Called outside the owner lock with only changed pair participants.
	// Maintenance must not turn a pair timeout into a network-wide invalidation.
	OnRuntimeUpdate func(networkID string, members map[string]struct{})
}

type clientRequest struct {
	member  string
	request *fb.WGPathRequestT
}

type ownedPair struct {
	clientRequests []clientRequest // bounded replay cache; no independent mode state
}

// Owner is a single-use lifecycle authority over Registry/Coordinator.
// Operations share its gate; coordinator state locks are never held during I/O.
// Run is optional: deterministic callers can drive Poll themselves.
// No goroutine/timer/socket starts in NewOwner.
// Real membership/policy writes must enter through UpdateRegistry when wired;
// periodic rechecks alone do not make external writes atomic with dispatch.
type Owner struct {
	mu          sync.Mutex
	registry    *Registry
	coordinator *Coordinator
	config      OwnerConfig
	pairs       map[PairKey]*ownedPair
	ctx         context.Context
	cancel      context.CancelFunc
	stopped     atomic.Bool
	running     bool
}

var ErrOwnerStopped = errors.New("WG path owner stopped")
var ErrNegotiationCapacity = errors.New("WG path negotiation capacity reached")

type BootstrapContext struct {
	AuthorityEpoch string
	Binding        MemberBinding
}

// Bootstrap is read-only and valid before the first runtime registration. The
// returned epoch belongs to this owner, never to a newly fabricated coordinator.
// Caller must send it only on the exact authenticated source connection and
// refresh after reconnect/restart; production snapshot wiring is gated separately.
func (o *Owner) Bootstrap(networkID string, sender types.SessionIdentity) (BootstrapContext, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.check(); err != nil {
		return BootstrapContext{}, err
	}
	binding, err := o.registry.Bootstrap(networkID, sender)
	if err != nil {
		return BootstrapContext{}, err
	}
	return BootstrapContext{AuthorityEpoch: o.coordinator.epoch, Binding: binding}, nil
}

func NewOwner(edgeID string, members MembershipReader, controls types.CurrentClientSessionReader, cfg OwnerConfig) (*Owner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	registry, err := NewRegistry(edgeID, members, controls, cfg.Registry)
	if err != nil {
		return nil, err
	}
	coordinator, err := NewCoordinator(edgeID, cfg.Budgets, cfg.MaxPairs)
	if err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	coordinator.transactionTimeout = cfg.TransactionTimeout
	ctx, cancel := context.WithCancel(context.Background())
	return &Owner{registry: registry, coordinator: coordinator, config: cfg,
		pairs: make(map[PairKey]*ownedPair), ctx: ctx, cancel: cancel}, nil
}

// Validate checks local configuration without attaching sources or starting an
// authority. NewOwner additionally validates its Edge and source dependencies.
func (cfg OwnerConfig) Validate() error {
	if cfg.Registry.Members <= 0 || cfg.MaxPairs <= 0 || cfg.ControlBurst <= 0 || cfg.TickInterval <= 0 ||
		cfg.TransactionTimeout < 0 || (cfg.TransactionTimeout > 0 && cfg.TransactionTimeout < time.Millisecond) {
		return fmt.Errorf("invalid WG owner configuration")
	}
	return cfg.Budgets.validate()
}

func (o *Owner) check() error {
	if o.stopped.Load() {
		return ErrOwnerStopped
	}
	return nil
}

func definitiveRevocation(err error) bool {
	return errors.Is(err, ErrMembershipRevoked) || errors.Is(err, ErrCoordinationAccessRevoked)
}

func (o *Owner) Snapshot(pair PairKey) (Snapshot, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.pairs[pair] == nil {
		return Snapshot{}, false
	}
	return o.coordinator.Snapshot(pair)
}
