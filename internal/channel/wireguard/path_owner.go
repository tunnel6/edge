package wireguard

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/internal/channel/wireguard/pathcoord"
	logger "icool.io/yat/edge/pkg/log"
)

// pathSourceGate protects owner attachment against manager writes. Lock order:
// source gate -> Owner -> member -> network. Snapshot reads never take this gate.
// Relay operations, pushes and upper-level coordinator callbacks stay outside it.
type pathSourceGate struct {
	sync.RWMutex
	current *PathOwner
}

// PathOwner binds one authority lifetime to the real managers. MemberManager
// constructs the source binding; MeshCoordinator also attaches its handler.
type PathOwner struct {
	owner          *pathcoord.Owner
	network        *NetworkManager
	handler        *WireGuardHandler // immutable after MeshCoordinator construction
	mesh           *MeshCoordinator  // nil for source-only/offline construction
	detachControls func()            // immutable after source construction
	runOnce        atomic.Bool
}

// NewPathOwner assembles an authority using the same managers as the handler.
// Proxy setup calls it only through explicit path_coordination configuration;
// absent configuration keeps the default off. Run remains explicit.
// Lifecycle shutdown releases both source and ingress.
func (c *MeshCoordinator) NewPathOwner(handler *WireGuardHandler, edgeID string, controls types.CurrentClientSessionReader, cfg pathcoord.OwnerConfig) (*PathOwner, error) {
	if c == nil || handler == nil || handler.coordinator != c || handler.edgeID != edgeID ||
		c.MemberManager == nil || c.NetworkManager == nil || c.MemberManager.networkManager != c.NetworkManager {
		return nil, fmt.Errorf("WG path assembly requires matching handler, Edge and managers")
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	cfg.OnRuntimeUpdate = func(networkID string, members map[string]struct{}) {
		_ = handler.pushNetworkEvent(networkID, fb.WGNetworkEventActionRUNTIME_UPDATE, members)
	}
	p, err := c.MemberManager.NewPathOwner(edgeID, controls, cfg)
	if err != nil {
		return nil, err
	}
	if err := handler.AttachPathControlReceiver(p.owner); err != nil {
		p.Stop()
		return nil, err
	}
	p.handler = handler
	p.mesh = c
	return p, nil
}

func (m *MemberManager) NewPathOwner(edgeID string, controls types.CurrentClientSessionReader, cfg pathcoord.OwnerConfig) (*PathOwner, error) {
	if m == nil || m.networkManager == nil {
		return nil, fmt.Errorf("WG path owner requires real membership/network managers")
	}
	nm := m.networkManager
	nm.pathSources.Lock()
	defer nm.pathSources.Unlock()
	if nm.pathSources.current != nil {
		return nil, fmt.Errorf("WG path owner already attached to managers")
	}
	owner, err := pathcoord.NewOwner(edgeID, m, controls, cfg)
	if err != nil {
		return nil, err
	}
	p := &PathOwner{owner: owner, network: nm}
	if source, ok := controls.(types.ClientSessionMutationSource); ok {
		p.detachControls, err = source.BindClientSessionMutations(p.changeSource)
		if err != nil {
			owner.Stop()
			return nil, err
		}
	}
	nm.pathSources.current = p
	return p, nil
}

// Owner exposes the transaction/ingress API for explicit construction-time wiring.
// Stop/Run belong to PathOwner so that source binding is released as well.
func (p *PathOwner) Owner() *pathcoord.Owner { return p.owner }

func (p *PathOwner) Run(ctx context.Context) error {
	if !p.runOnce.CompareAndSwap(false, true) {
		return fmt.Errorf("WG managed path owner already run")
	}
	defer p.Stop()
	return p.owner.Run(ctx)
}

func (p *PathOwner) Stop() {
	// Cancel sends before waiting for source writers, which may be waiting for
	// Owner's gate. No source attachment lock is held while stopping the owner.
	p.owner.Stop()
	if p.detachControls != nil {
		p.detachControls()
	}
	if p.handler != nil {
		p.handler.pathControlMu.Lock()
		if p.handler.pathControl == p.owner {
			p.handler.pathControl = nil
		}
		p.handler.pathControlMu.Unlock()
	}
	p.network.pathSources.Lock()
	defer p.network.pathSources.Unlock()
	if p.network.pathSources.current == p {
		p.network.pathSources.current = nil
	}
}

func (m *NetworkManager) stopPathOwner() {
	if m == nil {
		return
	}
	m.pathSources.RLock()
	p := m.pathSources.current
	m.pathSources.RUnlock()
	if p != nil {
		p.Stop()
	}
}

// pathSourceChange preserves the manager operation's return value. A refresh
// failure is an independent control-plane fault, not evidence that a persisted
// write failed. Owner revalidates the registry again before every future send.
func pathSourceChange(m *NetworkManager, change func() error) error {
	m.pathSources.RLock()
	defer m.pathSources.RUnlock()
	p := m.pathSources.current
	if p == nil {
		return change()
	}
	return p.changeSource(change)
}

// changeSource is also used by a bound real session source, whose attachment
// lock is independent of the network source lock. Never acquire either source
// attachment lock while already inside Owner.
func (p *PathOwner) changeSource(change func() error) error {
	called := false
	var changeErr error
	err := p.owner.UpdateRegistry(func() error {
		called = true
		changeErr = change()
		return changeErr
	})
	if !called && errors.Is(err, pathcoord.ErrOwnerStopped) {
		// A stopped authority cannot dispatch again. Leave/delete/admin writes
		// must remain available even before its lifecycle wrapper detaches it.
		return change()
	}
	if err != nil && changeErr == nil {
		logger.Warnf("WG path registry refresh after source write: %v", err)
	}
	if !called {
		return err
	}
	return changeErr
}

func pathSourceValue[T any](m *NetworkManager, change func() (T, error)) (T, error) {
	var value T
	err := pathSourceChange(m, func() error {
		var err error
		value, err = change()
		return err
	})
	return value, err
}
