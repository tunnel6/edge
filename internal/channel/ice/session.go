package ice

import (
	"fmt"
	"sync"
	"time"

	p2p "icool.io/yat/edge/internal/channel/p2p"
	"icool.io/yat/edge/internal/channel/p2p/negotiation"
)

type Session struct {
	ID                 string
	TunnelID           string
	PublisherSessionID string
	ConsumerSessionID  string

	State    State
	Strategy PunchStrategy

	PublisherEndpoint *PeerEndpoint
	ConsumerEndpoint  *PeerEndpoint

	Ufrag    string
	Pwd      string
	PubToken string
	ConToken string

	QuicRolePublisher QuicRole
	QuicRoleConsumer  QuicRole

	PunchResult *PunchResult
	QuicConn    *QuicConnInfo

	CreatedAt time.Time
	UpdatedAt time.Time
	Error     string

	punchBarrier negotiation.Barrier
	mu           sync.Mutex
}

func NewSession(tunnelID, publisherSessionID, consumerSessionID string) (*Session, error) {
	ufrag, err := GenerateUfrag()
	if err != nil {
		return nil, fmt.Errorf("generate ufrag: %w", err)
	}
	pwd, err := GeneratePwd()
	if err != nil {
		return nil, fmt.Errorf("generate pwd: %w", err)
	}

	now := time.Now()
	id := fmt.Sprintf("ice:%s:%s", tunnelID, ufrag)
	return &Session{
		ID:                 id,
		TunnelID:           tunnelID,
		PublisherSessionID: publisherSessionID,
		ConsumerSessionID:  consumerSessionID,
		State:              StateIdle,
		Ufrag:              ufrag,
		Pwd:                pwd,
		PubToken:           ufrag[:16] + "pub" + ufrag[16:29],
		ConToken:           ufrag[:16] + "con" + ufrag[16:29],
		QuicRolePublisher:  QuicRoleServer,
		QuicRoleConsumer:   QuicRoleClient,
		CreatedAt:          now,
		UpdatedAt:          now,
		punchBarrier: negotiation.NewBarrier(
			negotiation.Context{AttemptID: id, Phase: string(StatePunching)},
			[2]string{publisherSessionID, consumerSessionID},
		),
	}, nil
}

var validTransitions = map[State][]State{
	StateIdle:       {StateGathering, StateClosed},
	StateGathering:  {StateChecking, StatePunching, StateFallback, StateFailed, StateClosed},
	StateChecking:   {StatePunching, StateFallback, StateFailed, StateClosed},
	StatePunching:   {StateConnecting, StateFallback, StateFailed, StateClosed},
	StateConnecting: {StateConnected, StateFallback, StateFailed, StateClosed},
}

func (s *Session) Transition(newState State) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	allowed, ok := validTransitions[s.State]
	if !ok {
		return fmt.Errorf("no transitions from terminal state %s", s.State)
	}
	for _, a := range allowed {
		if a == newState {
			s.State = newState
			s.UpdatedAt = time.Now()
			return nil
		}
	}
	return fmt.Errorf("invalid transition %s -> %s", s.State, newState)
}

func (s *Session) SetPublisherEndpoint(addr *PeerEndpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PublisherEndpoint = addr
	s.UpdatedAt = time.Now()
}

func (s *Session) SetConsumerEndpoint(addr *PeerEndpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ConsumerEndpoint = addr
	s.UpdatedAt = time.Now()
}

func (s *Session) BothEndpointsReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.PublisherEndpoint != nil && s.PublisherEndpoint.UDPAddr != nil &&
		s.ConsumerEndpoint != nil && s.ConsumerEndpoint.UDPAddr != nil
}

func (s *Session) DetermineStrategy() PunchStrategy {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.PublisherEndpoint == nil || s.ConsumerEndpoint == nil {
		return StrategyRelay
	}

	natA := s.PublisherEndpoint.NATType
	natB := s.ConsumerEndpoint.NATType

	if natA == p2p.NATSymmetric && natB == p2p.NATSymmetric {
		return StrategyRelay
	}
	if natA == p2p.NATSymmetric || natB == p2p.NATSymmetric {
		return StrategyPortPredict
	}
	return StrategyStandard
}

func (s *Session) GetState() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.State
}

func (s *Session) Snapshot() SessionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	snap := SessionSnapshot{
		ID:        s.ID,
		TunnelID:  s.TunnelID,
		State:     s.State,
		Strategy:  s.Strategy,
		Error:     s.Error,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
	}
	if s.PublisherEndpoint != nil {
		snap.PubNAT = s.PublisherEndpoint.NATType
	}
	if s.ConsumerEndpoint != nil {
		snap.ConNAT = s.ConsumerEndpoint.NATType
	}
	return snap
}

func (s *Session) EndpointAddrs() (publisherAddr, consumerAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.PublisherEndpoint != nil && s.PublisherEndpoint.UDPAddr != nil {
		publisherAddr = s.PublisherEndpoint.UDPAddr.String()
	}
	if s.ConsumerEndpoint != nil && s.ConsumerEndpoint.UDPAddr != nil {
		consumerAddr = s.ConsumerEndpoint.UDPAddr.String()
	}
	return publisherAddr, consumerAddr
}
