package server

import (
	"icool.io/yat/edge/internal/upstream/certmgr"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPairTokensCarryRoleAndRemainConsumedAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumed.json")
	manager := NewPairingManager("localhost:9443")
	if err := manager.SetStateFile(path); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{certmgr.RoleDevice, certmgr.RoleOwner} {
		token := manager.GenerateTokenForRole(role)
		got, err := manager.Verify(token)
		if err != nil || got != role {
			t.Fatalf("role=%q err=%v", got, err)
		}
		if _, err := manager.Verify(token); err == nil {
			t.Fatal("token replay accepted")
		}
		restarted := NewPairingManager("")
		if err := restarted.SetStateFile(path); err != nil {
			t.Fatal(err)
		}
		restarted.RegisterTokenForRole(token, certmgr.RoleOwner)
		if _, err := restarted.Verify(token); err == nil {
			t.Fatal("bootstrap replay after restart accepted")
		}
	}
	token := manager.GenerateToken()
	var successes atomic.Int32
	var workers sync.WaitGroup
	for range 12 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := manager.Verify(token); err == nil {
				successes.Add(1)
			}
		}()
	}
	workers.Wait()
	if successes.Load() != 1 {
		t.Fatalf("consumed %d times", successes.Load())
	}
}

func TestOwnerIsSessionBound(t *testing.T) {
	owner := &Session{UserID: "device:shared", Role: certmgr.RoleOwner}
	device := &Session{UserID: "device:shared", Role: certmgr.RoleDevice}
	if !(sessionOwnerVerifier{owner}).IsEdgeOwner(owner.UserID) {
		t.Fatal("owner denied")
	}
	if (sessionOwnerVerifier{device}).IsEdgeOwner(owner.UserID) {
		t.Fatal("device borrowed owner identity")
	}
	if (sessionOwnerVerifier{owner}).IsEdgeOwner("device:other") {
		t.Fatal("identity mismatch accepted")
	}
	if (sessionOwnerVerifier{}).IsEdgeOwner(owner.UserID) {
		t.Fatal("missing session accepted")
	}
}
