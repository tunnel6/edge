package relay

import (
	"net"
	"testing"
)

func TestCIDROverlaps(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"exact match", "10.0.0.0/24", "10.0.0.0/24", true},
		{"supernet contains subnet", "10.0.0.0/16", "10.0.1.0/24", true},
		{"subnet contained by supernet", "10.0.1.0/24", "10.0.0.0/16", true},
		{"no overlap", "10.0.0.0/24", "192.168.1.0/24", false},
		{"adjacent no overlap", "10.0.0.0/24", "10.0.1.0/24", false},
		{"cgnat vs private", "100.64.1.0/24", "10.0.0.0/24", false},
		{"invalid cidr", "not-a-cidr", "10.0.0.0/24", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CIDROverlaps(tt.a, tt.b); got != tt.want {
				t.Errorf("CIDROverlaps(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestGenerateSuggestedCIDRsFiltersForbidden(t *testing.T) {
	// Block the first CGNAT candidate.
	_, blocked, _ := net.ParseCIDR("100.64.1.0/24")
	forbidden := []net.IPNet{*blocked}

	result := GenerateSuggestedCIDRs(forbidden, nil)

	for _, cidr := range result {
		if cidr == "100.64.1.0/24" {
			t.Fatal("suggested a CIDR that is in the forbidden list")
		}
	}
	if len(result) == 0 {
		t.Fatal("expected at least one suggestion")
	}
	if len(result) > 5 {
		t.Fatalf("expected at most 5 suggestions, got %d", len(result))
	}
}

func TestGenerateSuggestedCIDRsFiltersExisting(t *testing.T) {
	existing := []string{"100.64.1.0/24", "100.64.2.0/24", "100.64.3.0/24", "100.65.1.0/24", "100.65.2.0/24"}

	result := GenerateSuggestedCIDRs(nil, existing)

	for _, cidr := range result {
		for _, e := range existing {
			if cidr == e {
				t.Fatalf("suggested %q which is already an existing network", cidr)
			}
		}
	}
}

func TestGenerateSuggestedCIDRsMaxFive(t *testing.T) {
	result := GenerateSuggestedCIDRs(nil, nil)
	if len(result) > 5 {
		t.Fatalf("expected at most 5 suggestions, got %d", len(result))
	}
	if len(result) == 0 {
		t.Fatal("expected at least one suggestion with no constraints")
	}
}

func TestGenerateSuggestedCIDRsEmptyCandidates(t *testing.T) {
	result := GenerateSuggestedCIDRsWithCandidates(nil, nil, nil)
	if len(result) != 0 {
		t.Fatalf("expected empty result with no candidates, got %d", len(result))
	}
}

func TestCidrOverlapsAny(t *testing.T) {
	_, subnet1, _ := net.ParseCIDR("10.0.0.0/24")
	_, subnet2, _ := net.ParseCIDR("192.168.1.0/24")
	forbidden := []net.IPNet{*subnet1, *subnet2}

	if !cidrOverlapsAny("10.0.0.0/16", forbidden) {
		t.Error("10.0.0.0/16 should overlap with 10.0.0.0/24")
	}
	if cidrOverlapsAny("172.16.0.0/24", forbidden) {
		t.Error("172.16.0.0/24 should not overlap with any forbidden")
	}
}
