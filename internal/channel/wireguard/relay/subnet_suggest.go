package relay

import "net"

// defaultSuggestedCandidates is the ordered pool of candidate CIDRs from which
// suggestions are drawn. CGNAT ranges (100.64.0.0/10) come first because they
// are least likely to collide with real infrastructure.
var defaultSuggestedCandidates = []string{
	"100.64.1.0/24",
	"100.64.2.0/24",
	"100.64.3.0/24",
	"100.65.1.0/24",
	"100.65.2.0/24",
	"10.10.0.0/24",
	"10.20.0.0/24",
	"10.30.0.0/24",
	"172.16.10.0/24",
	"172.16.20.0/24",
	"192.168.100.0/24",
	"192.168.200.0/24",
}

// GenerateSuggestedCIDRs returns up to 5 CIDRs from the candidate pool that do
// not overlap with any forbidden subnet or existing network CIDR.
func GenerateSuggestedCIDRs(forbidden []net.IPNet, existing []string) []string {
	return GenerateSuggestedCIDRsWithCandidates(defaultSuggestedCandidates, forbidden, existing)
}

// GenerateSuggestedCIDRsWithCandidates is the testable core of
// GenerateSuggestedCIDRs; it accepts an arbitrary candidate list.
func GenerateSuggestedCIDRsWithCandidates(candidates []string, forbidden []net.IPNet, existing []string) []string {
	var result []string
	for _, candidate := range candidates {
		if len(result) >= 5 {
			break
		}
		if cidrOverlapsAny(candidate, forbidden) {
			continue
		}
		if cidrOverlapsExisting(candidate, existing) {
			continue
		}
		result = append(result, candidate)
	}
	return result
}

// CIDROverlaps reports whether a and b overlap (one contains the other or they
// share addresses).
func CIDROverlaps(a, b string) bool {
	_, netA, errA := net.ParseCIDR(a)
	_, netB, errB := net.ParseCIDR(b)
	if errA != nil || errB != nil {
		return false
	}
	return netA.Contains(netB.IP) || netB.Contains(netA.IP)
}

// cidrOverlapsAny reports whether cidr overlaps with any subnet in the list.
func cidrOverlapsAny(cidr string, subnets []net.IPNet) bool {
	_, candidateNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	for i := range subnets {
		if subnets[i].Contains(candidateNet.IP) || candidateNet.Contains(subnets[i].IP) {
			return true
		}
	}
	return false
}

// cidrOverlapsExisting reports whether cidr overlaps with any existing network
// CIDR string.
func cidrOverlapsExisting(cidr string, existing []string) bool {
	for _, e := range existing {
		if CIDROverlaps(cidr, e) {
			return true
		}
	}
	return false
}
