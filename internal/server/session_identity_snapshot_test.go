package server

import (
	"sync"
	"testing"
)

func TestCurrentClientSessionSnapshotExcludesReplacedAndClosed(t *testing.T) {
	sm := NewSessionManager(8)
	first := NewSession("first", "user", "device", "host", nil)
	first.SetCapabilities([]string{"wg.path-coordination.v1"})
	first.SetScopeClaims([]string{"network:net"})
	sm.clientSessions.Store("device", first)
	identity, ok := sm.CurrentClientSession("device")
	if !ok || identity.SessionID != "first" || identity.UserID != "user" {
		t.Fatal("no current identity")
	}
	identity.Capabilities[0], identity.ScopeClaims[0] = "mutated", "mutated"
	copy, _ := sm.CurrentClientSession("device")
	if copy.Capabilities[0] == "mutated" || copy.ScopeClaims[0] == "mutated" {
		t.Fatal("snapshot aliases auth data")
	}
	second := NewSession("second", "user", "device", "host", nil)
	sm.clientSessions.Store("device", second)
	copy, ok = sm.CurrentClientSession("device")
	if !ok || copy.SessionID != "second" {
		t.Fatal("replacement not current")
	}
	second.mu.Lock()
	second.closed = true
	second.mu.Unlock()
	if _, ok := sm.CurrentClientSession("device"); ok {
		t.Fatal("closed session accepted")
	}
	if _, ok := sm.CurrentClientSession("missing"); ok {
		t.Fatal("missing session accepted")
	}
}

func TestCurrentClientSessionSnapshotConcurrentReplacement(t *testing.T) {
	sm := NewSessionManager(8)
	first := NewSession("first", "user", "device", "host", nil)
	second := NewSession("second", "user", "device", "host", nil)
	sm.clientSessions.Store("device", first)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 100; j++ {
				sm.clientSessions.Store("device", first)
				first.SetCapabilities([]string{"wg.path-coordination.v1"})
				sm.clientSessions.Store("device", second)
				identity, ok := sm.CurrentClientSession("device")
				if ok && (identity.DeviceID != "device" || identity.UserID != "user") {
					t.Error("inconsistent snapshot")
				}
			}
		}()
	}
	workers.Wait()
}
