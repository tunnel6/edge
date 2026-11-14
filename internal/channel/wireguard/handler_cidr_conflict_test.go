package wireguard

import (
	"errors"
	"net"
	"testing"
)

func TestCIDRConflictErrorIsDetected(t *testing.T) {
	err := &CIDRConflictError{
		CIDR:            "10.0.0.0/24",
		ConflictingWith: "10.0.0.0/24",
		SuggestedCIDRs:  []string{"100.64.1.0/24", "100.64.2.0/24"},
	}

	if !IsCIDRConflict(err) {
		t.Fatal("IsCIDRConflict should return true for *CIDRConflictError")
	}

	extracted := AsCIDRConflict(err)
	if extracted == nil {
		t.Fatal("AsCIDRConflict should return non-nil for *CIDRConflictError")
	}
	if len(extracted.SuggestedCIDRs) != 2 {
		t.Fatalf("expected 2 suggestions, got %d", len(extracted.SuggestedCIDRs))
	}
}

func TestCIDRConflictErrorNotDetectedForGenericError(t *testing.T) {
	err := errors.New("some generic error")

	if IsCIDRConflict(err) {
		t.Fatal("IsCIDRConflict should return false for generic error")
	}
	if AsCIDRConflict(err) != nil {
		t.Fatal("AsCIDRConflict should return nil for generic error")
	}
}

func TestNetworkManagerCheckCIDRAgainstLocalSubnets(t *testing.T) {
	nm := NewNetworkManager()

	_, subnet1, _ := net.ParseCIDR("10.0.0.0/24")
	_, subnet2, _ := net.ParseCIDR("192.168.1.0/24")
	nm.SetForbiddenSubnets([]net.IPNet{*subnet1, *subnet2})

	// checkCIDRAgainstLocalSubnetsLocked requires the caller to hold the lock.
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	// Should conflict with 10.0.0.0/24.
	conflict := nm.checkCIDRAgainstLocalSubnetsLocked("10.0.0.0/24")
	if conflict == nil {
		t.Fatal("expected conflict for 10.0.0.0/24")
	}
	if conflict.ConflictingWith != "10.0.0.0/24" {
		t.Fatalf("conflicting subnet = %q, want 10.0.0.0/24", conflict.ConflictingWith)
	}
	if len(conflict.SuggestedCIDRs) == 0 {
		t.Fatal("expected at least one suggestion")
	}

	// Should conflict with 192.168.1.0/24.
	conflict = nm.checkCIDRAgainstLocalSubnetsLocked("192.168.1.0/24")
	if conflict == nil {
		t.Fatal("expected conflict for 192.168.1.0/24")
	}

	// Should NOT conflict with 172.16.0.0/24.
	conflict = nm.checkCIDRAgainstLocalSubnetsLocked("172.16.0.0/24")
	if conflict != nil {
		t.Fatalf("unexpected conflict for 172.16.0.0/24: %v", conflict)
	}

	// A supernet that contains a forbidden subnet should also conflict.
	conflict = nm.checkCIDRAgainstLocalSubnetsLocked("10.0.0.0/16")
	if conflict == nil {
		t.Fatal("expected conflict for 10.0.0.0/16 (contains 10.0.0.0/24)")
	}
}

func TestNetworkManagerCheckCIDRNoForbiddenSubnets(t *testing.T) {
	nm := NewNetworkManager()

	nm.mu.RLock()
	defer nm.mu.RUnlock()

	// With no forbidden subnets, nothing should conflict.
	conflict := nm.checkCIDRAgainstLocalSubnetsLocked("10.0.0.0/24")
	if conflict != nil {
		t.Fatalf("unexpected conflict with no forbidden subnets: %v", conflict)
	}
}
