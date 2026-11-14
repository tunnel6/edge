// Package pathcoord defines and coordinates native WG pair transactions. It
// performs no network I/O or WG mutation; production takeover remains gated.
package pathcoord

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"unicode/utf8"

	fb "icool.io/yat/api/build/fb/golang/message"
)

const Capability = "wg.path-coordination.v1"
const MaxCandidates = 32

// PairKey is comparable, collision-free and independent of who initiates.
type PairKey struct {
	NetworkID string
	MemberAID string
	MemberBID string
}

func NewPairKey(networkID, first, second string) (PairKey, error) {
	if !validID(networkID) || !validID(first) || !validID(second) || first == second {
		return PairKey{}, fmt.Errorf("invalid WG pair identity")
	}
	if first > second {
		first, second = second, first
	}
	return PairKey{networkID, first, second}, nil
}

func validID(id string) bool {
	return len(id) > 0 && len(id) <= 256 && utf8.ValidString(id) &&
		strings.TrimSpace(id) == id && !strings.ContainsRune(id, '\x00')
}

func validKey(key string) bool {
	b, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(b) == 32 && key == base64.StdEncoding.EncodeToString(b) && !bytes.Equal(b, make([]byte, 32))
}

func ValidateMember(m *fb.WGPathMemberContextT) error {
	if m == nil || !validID(m.MemberId) || !validID(m.DeviceId) || !validKey(m.PublicKey) ||
		!validID(m.MembershipGeneration) || !validID(m.RuntimeGeneration) || !validID(m.NetworkEnvironment) {
		return fmt.Errorf("invalid WG path member identity/generation")
	}
	ip, err := netip.ParseAddr(m.AssignedIp)
	if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" || ip.Is4In6() {
		return fmt.Errorf("invalid WG member address")
	}
	if m.CandidateRevision == 0 || len(m.Candidates) > MaxCandidates || (m.ProbeReady && m.ProbePort == 0) {
		return fmt.Errorf("invalid WG runtime/candidate readiness")
	}
	for _, c := range m.Candidates {
		if c == nil || !validEndpoint(c.Endpoint) || c.Kind < fb.WGPathCandidateKindLAN ||
			c.Kind > fb.WGPathCandidateKindAUTHENTICATED_DIRECT {
			return fmt.Errorf("invalid WG endpoint candidate")
		}
	}
	return nil
}

func validEndpoint(endpoint string) bool {
	a, err := netip.ParseAddrPort(endpoint)
	return err == nil && a.Port() != 0 && a.Addr().Zone() == "" &&
		!a.Addr().IsUnspecified() && !a.Addr().IsMulticast() && !a.Addr().Is4In6()
}

func ownsHost(cidrs []string, host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, cidr := range cidrs {
		p, err := netip.ParsePrefix(cidr)
		if err == nil && p.Addr() == ip && p.Bits() == ip.BitLen() {
			return true
		}
	}
	return false
}

func ValidateRequest(request *fb.WGPathRequestT) error {
	if request == nil || !validID(request.NetworkId) || !validID(request.PeerMemberId) ||
		!validID(request.RequestId) || !validID(request.ObservedAuthorityEpoch) ||
		request.RequestedPath > fb.WGPathTypeRELAY || request.TargetPath > fb.WGPathTypeRELAY {
		return fmt.Errorf("invalid WG request identity/path/authority")
	}
	switch request.Kind {
	case fb.WGPathRequestKindSYNC_MODE:
		if request.LocalMode == nil || request.LocalMode.Mode > fb.WGPathTypeRELAY || request.RequestedPath != fb.WGPathTypeUNKNOWN {
			return fmt.Errorf("invalid WG saved mode restore")
		}
	case fb.WGPathRequestKindCHANGE_MODE, fb.WGPathRequestKindSWITCH_PATH:
		if request.LocalMode != nil {
			return fmt.Errorf("WG proposal cannot carry saved mode facts")
		}
		if request.Kind == fb.WGPathRequestKindSWITCH_PATH && request.RequestedPath == fb.WGPathTypeUNKNOWN {
			return fmt.Errorf("WG Auto proposal needs a concrete path")
		}
	default:
		return fmt.Errorf("unknown WG request kind")
	}
	return nil
}

func cloneMode(setting *fb.WGPathModeSettingT) *fb.WGPathModeSettingT {
	if setting == nil {
		return nil
	}
	copy := *setting
	return &copy
}

func sameMode(a, b *fb.WGPathModeSettingT) bool { return reflect.DeepEqual(a, b) }
