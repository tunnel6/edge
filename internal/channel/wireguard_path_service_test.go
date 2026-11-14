package channel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/internal/channel/wireguard"
	"icool.io/yat/edge/internal/channel/wireguard/pathcoord"
	"icool.io/yat/edge/pkg/config"
)

type pathServiceTransport struct {
	mu       sync.Mutex
	bound    bool
	binds    atomic.Int32
	detaches atomic.Int32
	bindHook func()
}

func (*pathServiceTransport) PushToClient(string, []byte) error   { return nil }
func (*pathServiceTransport) AsyncPushToClients([]string, []byte) {}
func (*pathServiceTransport) CurrentClientSession(device string) (types.SessionIdentity, bool) {
	return types.SessionIdentity{DeviceID: device, UserID: "user", SessionID: "session-" + device, Capabilities: []string{pathcoord.Capability}}, true
}
func (p *pathServiceTransport) BindClientSessionMutations(func(func() error) error) (func(), error) {
	p.mu.Lock()
	if p.bound {
		p.mu.Unlock()
		return nil, fmt.Errorf("already bound")
	}
	p.bound = true
	p.mu.Unlock()
	p.binds.Add(1)
	if p.bindHook != nil {
		p.bindHook()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			p.bound = false
			p.mu.Unlock()
			p.detaches.Add(1)
		})
	}, nil
}

func pathServiceConfig() *config.WireGuardPathConfig {
	c := &config.WireGuardPathConfig{
		TransactionTimeout: time.Minute,
		RegistryMembers:    8, MaxPairs: 8, ControlBurst: 64,
		TickInterval: time.Millisecond,
	}
	c.Phases.Prepare, c.Phases.Apply = time.Second, time.Second
	return c
}

func pathServiceFixture(t *testing.T, cfg *config.WireGuardPathConfig) (*ChannelManager, *Config, *pathServiceTransport) {
	t.Helper()
	p := &pathServiceTransport{}
	// No relay manager, real WG interface, helper or network listener. The real
	// in-memory managers, handler, service lifecycle and Owner ticker are used.
	m := &ChannelManager{wgCoordinator: wireguard.NewMeshCoordinator(), clientPusher: p}
	c := &Config{DomainProvider: &staticDomainProvider{assigned: "edge.example.com"}, EdgeID: "edge", StatusDir: t.TempDir(), WireGuardEnabled: true, WireGuardPathCoordination: cfg}
	if err := m.ApplyConfig(c); err != nil {
		t.Fatal(err)
	}
	mesh := m.wgCoordinator.(*wireguard.MeshCoordinator)
	for i, id := range []string{"net", "other"} {
		if _, err := mesh.NetworkManager.CreateNetwork(&wireguard.CreateNetworkRequest{ID: id, CIDR: fmt.Sprintf("10.24.%d.0/24", i), CoordinatorEdgeID: "edge", RelayMode: wireguard.RelayModeOptional}); err != nil {
			t.Fatal(err)
		}
		for j, member := range []string{"a", "b"} {
			if _, err := mesh.MemberManager.JoinNetwork(&wireguard.JoinNetworkRequest{NetworkID: id, MemberID: id + member, ClientID: member, PublicKey: []string{"IGYpnCCyZzdQinF1VI+lkNUVfkrXUe53ptWFS2izmSo=", "x8ABrq5+cQiOV7p2VzAC1HNCcsI2+GxOWbO5AjtF4Ao="}[j]}); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() {
		if err := m.Stop(); err != nil {
			t.Error(err)
		}
	})
	return m, c, p
}

func registerPathServiceMembers(t *testing.T, s *wireGuardPathService) {
	t.Helper()
	for _, id := range []string{"a", "b"} {
		sender, _ := s.transport.CurrentClientSession(id)
		b, err := s.owner.Owner().Bootstrap("net", sender)
		if err != nil {
			t.Fatal(err)
		}
		err = s.owner.Owner().HandlePathControl(sender, pathcoord.ControlMessage{Runtime: &fb.WGPathRuntimeReportT{
			NetworkId: "net", AuthorityEpoch: b.AuthorityEpoch, NetworkPolicyRevision: b.Binding.Network.PolicyRevision,
			Member: &fb.WGPathMemberContextT{MemberId: b.Binding.Member.MemberID, MembershipGeneration: b.Binding.Member.Generation,
				RuntimeGeneration: "fixture-runtime-" + id, NetworkEnvironment: "fixture-env", CandidateRevision: 1},
		}})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestWireGuardPathServiceRunReloadStopAndFreshAuthority(t *testing.T) {
	m, cfg, p := pathServiceFixture(t, pathServiceConfig())
	s := m.wgPathService
	if s.owner != nil || p.binds.Load() != 0 {
		t.Fatal("setup started an authority")
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	first := s.owner
	sender, _ := p.CurrentClientSession("a")
	boot, err := first.Owner().Bootstrap("net", sender)
	if err != nil {
		t.Fatal(err)
	}
	registerPathServiceMembers(t, s)
	handler, pc := m.wgHandler, m.wgP2P
	if err := m.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if m.wgPathService != s || s.owner != first || m.wgHandler != handler || m.wgP2P != pc || p.binds.Load() != 1 {
		t.Fatal("reload replaced the authority or writer fences")
	}
	if live, _ := m.p2pRuntime.Get("wireguard"); live != pc {
		t.Fatal("reload reset the live P2P namespace")
	}
	changed := *cfg
	changed.WireGuardPathCoordination = nil
	if err := m.ApplyConfig(&changed); err == nil || m.config != cfg || m.wgHandler != handler {
		t.Fatal("unsafe reload changed live state", err)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if p.detaches.Load() != 1 {
		t.Fatal("stop did not release exact source binding")
	}
	if _, err := first.Owner().Bootstrap("net", sender); !errors.Is(err, pathcoord.ErrOwnerStopped) {
		t.Fatal("old authority survived stop", err)
	}
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	fresh, err := s.owner.Owner().Bootstrap("net", sender)
	if err != nil || fresh.AuthorityEpoch == boot.AuthorityEpoch || p.binds.Load() != 2 {
		t.Fatal("restart reused the old authority", err)
	}
}

func TestWireGuardPathServiceStopDuringStartupRetainsOwnership(t *testing.T) {
	m, _, p := pathServiceFixture(t, pathServiceConfig())
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	p.bindHook = func() { close(entered); <-release }
	start := make(chan error, 1)
	go func() { start <- m.wgPathService.Start() }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("startup did not bind sources")
	}
	stop := make(chan error, 2)
	go func() { stop <- m.wgPathService.Stop() }()
	go func() { stop <- m.wgPathService.Stop() }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		m.wgPathService.mu.Lock()
		stopping := m.wgPathService.stopping
		m.wgPathService.mu.Unlock()
		if stopping == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stop did not cancel startup")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-stop:
		t.Fatalf("stop lost in-flight startup: %v", err)
	default:
	}
	unblock()
	select {
	case err := <-start:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled startup succeeded", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled startup did not finish")
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-stop:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("stop did not join startup")
		}
	}
	if p.binds.Load() != p.detaches.Load() {
		t.Fatal("cancelled startup leaked sources")
	}
}

func TestWireGuardPathServiceConfigurationIsExplicitAndCopied(t *testing.T) {
	m, cfg, _ := pathServiceFixture(t, pathServiceConfig())
	cfg.WireGuardPathCoordination.MaxPairs = 999
	if m.wgPathService.config.MaxPairs != 8 {
		t.Fatal("caller mutated live config")
	}
	if err := m.ApplyConfig(cfg); err == nil {
		t.Fatal("mutated configuration reloaded")
	}
	plain, c, _ := pathServiceFixture(t, nil)
	if plain.wgPathService != nil {
		t.Fatal("default setup enables coordination")
	}
	c.WireGuardPathCoordination = pathServiceConfig()
	plain.clientPusher = newRecordingClientPusher()
	if err := plain.ApplyConfig(c); err == nil {
		t.Fatal("legacy broadcaster was accepted as exact transport")
	}
}
