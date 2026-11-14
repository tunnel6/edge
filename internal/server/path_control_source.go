package server

import (
	"fmt"
	"sync"

	"icool.io/yat/edge/internal/channel/types"
)

var _ types.ClientSessionMutationSource = (*SessionManager)(nil)

type clientSessionMutationBinding struct {
	gate func(func() error) error
}

type clientSessionMutations struct {
	sync.RWMutex
	current *clientSessionMutationBinding
}

func (sm *SessionManager) BindClientSessionMutations(gate func(func() error) error) (func(), error) {
	if gate == nil {
		return nil, fmt.Errorf("missing client session mutation gate")
	}
	sm.pathMutations.Lock()
	defer sm.pathMutations.Unlock()
	if sm.pathMutations.current != nil {
		return nil, fmt.Errorf("client session mutation gate already bound")
	}
	binding := &clientSessionMutationBinding{gate: gate}
	sm.pathMutations.current = binding
	return func() {
		sm.pathMutations.Lock()
		defer sm.pathMutations.Unlock()
		if sm.pathMutations.current == binding {
			sm.pathMutations.current = nil
		}
	}, nil
}

func (sm *SessionManager) changeClientSession(change func() error) error {
	sm.pathMutations.RLock()
	defer sm.pathMutations.RUnlock()
	if binding := sm.pathMutations.current; binding != nil {
		return binding.gate(change)
	}
	return change()
}

// Hold controlSourceMu across selection and mutation. Add takes its write lock
// through publication, so a setter that saw no manager cannot finish after the
// session has become live and bypass the newly bound authority.
func (s *Session) changeControlFacts(change func() error) error {
	s.controlSourceMu.RLock()
	defer s.controlSourceMu.RUnlock()
	if s.controlSource != nil {
		return s.controlSource.changeClientSession(change)
	}
	return change()
}

// SetScopeClaims owns its input and serializes live certificate-scope changes
// with the authority. Authentication-time initialization uses the same API.
func (s *Session) SetScopeClaims(claims []string) {
	_ = s.changeControlFacts(func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.ScopeClaims = append([]string(nil), claims...)
		return nil
	})
}

// closeState only withdraws control facts; TLS close_notify and transport I/O
// must run after the source gate. Caller owns physical cleanup when true.
func (s *Session) closeState() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.closed = true
	close(s.closeCh)
	for _, ch := range s.Channels {
		ch.Close()
	}
	return true
}

func (s *Session) closeTransport() error {
	if s.Conn == nil {
		return nil
	}
	return s.Conn.Close()
}
