package channel

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/internal/channel/wireguard"
	"icool.io/yat/edge/internal/channel/wireguard/pathcoord"
	"icool.io/yat/edge/internal/channel/wireguard/relay"
	"icool.io/yat/edge/pkg/config"
	logger "icool.io/yat/edge/pkg/log"
)

type pathOwnerTransport interface {
	types.CurrentClientSessionReader
	types.ClientSessionMutationSource
}

// The manager retains this service across reloads, including its exact handler,
// source bindings and authority. Stop joins Run before the Mesh/relay is stopped.
type wireGuardPathService struct {
	config      config.WireGuardPathConfig
	ownerConfig pathcoord.OwnerConfig
	mesh        *wireguard.MeshCoordinator
	handler     *wireguard.WireGuardHandler
	transport   pathOwnerTransport
	edgeID      string
	operation   sync.Mutex
	mu          sync.Mutex
	cancel      context.CancelFunc
	stopping    int // pending Stop calls; one caller cannot reopen another's fence
	owner       *wireguard.PathOwner
	done        chan struct{}
	runErr      error
}

func pathOwnerConfig(c *config.WireGuardPathConfig) (pathcoord.OwnerConfig, error) {
	if c == nil {
		return pathcoord.OwnerConfig{}, fmt.Errorf("WG path coordination configuration is nil")
	}
	owner := pathcoord.OwnerConfig{
		TransactionTimeout: c.TransactionTimeout,
		Budgets:            pathcoord.Budgets{Prepare: c.Phases.Prepare, Apply: c.Phases.Apply},
		Registry:           pathcoord.RegistryLimits{Members: c.RegistryMembers},
		MaxPairs:           c.MaxPairs, ControlBurst: c.ControlBurst,
		TickInterval: c.TickInterval,
	}
	if err := owner.Validate(); err != nil {
		return owner, err
	}
	return owner, nil
}

// Called before ApplyConfig changes live state. A reload must not silently drop
// an authority, change its budgets or replace the handler/P2P retirement fences.
func (m *ChannelManager) checkWireGuardPathConfig(cfg *Config) error {
	if m.wgPathService != nil {
		if !cfg.WireGuardEnabled || cfg.EdgeID != m.wgPathService.edgeID || cfg.WireGuardPathCoordination == nil ||
			!reflect.DeepEqual(*cfg.WireGuardPathCoordination, m.wgPathService.config) {
			return fmt.Errorf("WG path authority/budget changes require a process restart")
		}
		return nil
	}
	if cfg.WireGuardPathCoordination == nil {
		return nil
	}
	if m.started || !cfg.WireGuardEnabled || cfg.EdgeID == "" {
		return fmt.Errorf("WG path coordination requires WireGuard, an Edge identity and startup assembly")
	}
	if _, ok := m.clientPusher.(pathOwnerTransport); !ok {
		return fmt.Errorf("WG path coordination requires the real session reader, mutation source and exact-session sender")
	}
	_, err := pathOwnerConfig(cfg.WireGuardPathCoordination)
	return err
}

func (m *ChannelManager) setupWireGuardPathService(cfg *Config) error {
	logger.Infof("[PathService] setupWireGuardPathService called, WireGuardPathCoordination=%v", cfg.WireGuardPathCoordination != nil)
	if cfg.WireGuardPathCoordination == nil {
		logger.Infof("[PathService] WireGuardPathCoordination is nil, skipping setup")
		return nil
	}
	logger.Infof("[PathService] WireGuardPathCoordination configured")
	if m.wgPathService == nil {
		mesh, ok := m.wgCoordinator.(*wireguard.MeshCoordinator)
		if !ok {
			return fmt.Errorf("WG path coordination requires the real Mesh coordinator")
		}
		if _, observed := mesh.GetRelayManager().(relay.ObservationSource); observed {
			if _, serialized := mesh.GetRelayManager().(relay.ObservationMutationSource); !serialized {
				return fmt.Errorf("WG path observation source requires a lifetime mutation gate")
			}
		}
		handler, ok := m.wgHandler.(*wireguard.WireGuardHandler)
		if !ok {
			return fmt.Errorf("WG path coordination requires the matching real handler")
		}
		transport, ok := m.clientPusher.(pathOwnerTransport)
		if !ok {
			return fmt.Errorf("WG path session transport unavailable")
		}
		ownerConfig, err := pathOwnerConfig(cfg.WireGuardPathCoordination)
		if err != nil {
			return err
		}
		copy := *cfg.WireGuardPathCoordination
		m.wgPathService = &wireGuardPathService{config: copy, ownerConfig: ownerConfig, mesh: mesh, handler: handler, transport: transport, edgeID: cfg.EdgeID}
	}
	m.managedServices = append(m.managedServices, m.wgPathService)
	return nil
}

func (s *wireGuardPathService) Start() error {
	logger.Infof("[PathService] Start() called")
	s.operation.Lock()
	defer s.operation.Unlock()
	s.mu.Lock()
	if s.stopping != 0 {
		s.mu.Unlock()
		return fmt.Errorf("[PathService] Start() aborted: service is stopping")
	}
	s.mu.Unlock()
	if s.owner != nil {
		select {
		case <-s.done:
			return fmt.Errorf("WG path owner exited; stop must complete before restarting: %w", s.runErr)
		default:
			logger.Infof("[PathService] Start() skipped: owner already running")
			return nil
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	if s.stopping != 0 {
		s.mu.Unlock()
		cancel()
		return fmt.Errorf("WG path service is stopping")
	}
	s.cancel = cancel
	s.mu.Unlock()
	started := false
	defer func() {
		if !started {
			cancel()
			s.mu.Lock()
			s.cancel = nil
			s.mu.Unlock()
		}
	}()
	owner, err := s.mesh.NewPathOwner(s.handler, s.edgeID, s.transport, s.ownerConfig)
	if err != nil {
		return err
	}
	defer func() {
		if !started {
			owner.Stop()
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.owner, s.done, s.runErr = owner, make(chan struct{}), nil
	done := s.done
	go func() { s.runErr = owner.Run(ctx); close(done) }()
	started = true
	logger.Infof("[PathService] Start() succeeded, owner running in background")
	return nil
}

func (s *wireGuardPathService) Stop() error {
	// Cancel outside the operation lock: startup may be waiting for an older
	// legacy send to drain. Stop must interrupt that wait too.
	s.mu.Lock()
	s.stopping++
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.operation.Lock()
	defer s.operation.Unlock()
	defer func() { s.mu.Lock(); s.stopping--; s.mu.Unlock() }()
	if s.owner == nil {
		return nil
	}
	s.owner.Stop()
	<-s.done
	err := s.runErr
	s.owner = nil
	s.mu.Lock()
	s.cancel = nil
	s.mu.Unlock()
	if errors.Is(err, context.Canceled) || errors.Is(err, pathcoord.ErrOwnerStopped) {
		return nil
	}
	return err
}
