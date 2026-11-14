package pathcoord

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"

	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
)

// Membership is supplied by the Edge membership authority, never by a runtime
// message. Generation must change on leave/rejoin and identity/key/IP changes.
// A disconnected member remains eligible; an explicitly revoked member does not.
type Membership struct {
	MemberID, DeviceID, PublicKey, AssignedIP, Generation string
	ObservedEndpoint                                      string
	ObservedAt                                            uint64
	// Local source clock, not reconstructed from a client's wire timestamp.
	// This is endpoint acceptance time, not evidence of the latest WG packet.
	EndpointAcceptedAt  time.Time
	GenerationStartedAt time.Time // local generation fence for raw observer reads
}

type NetworkBinding struct {
	NetworkID, CoordinatorID, RelayPublicKey string
	PolicyRevision                           uint64
	RelayMode                                fb.WGRelayMode
}

type MemberBinding struct {
	Network NetworkBinding
	Member  Membership
}

type PairBinding struct {
	Network NetworkBinding
	Members [2]Membership // canonical pair order
}

// MembershipReader must copy under the real managers' locks, reject inactive
// networks, revoked/relay members and return Edge-issued generations. Pair reads
// must be atomic with respect to network policy and both member identities.
// Legacy getters returning live pointers do not implement this contract.
type MembershipReader interface {
	PathMember(networkID, authenticatedDeviceID string) (MemberBinding, error)
	PathPair(PairKey) (PairBinding, error)
}

// ErrMembershipRevoked distinguishes definitive removal/revocation from a
// temporary storage/authority failure. Only the former permits record cleanup.
var ErrMembershipRevoked = errors.New("WG path membership revoked")

// ErrCoordinationAccessRevoked is a definitive live capability/scope/authority
// loss. It differs from offline control or a temporary registry lookup failure.
var ErrCoordinationAccessRevoked = errors.New("WG path coordination access revoked")

type RegistryLimits struct {
	Members int
}

type runtimeKey struct{ network, member string }
type runtimeRecord struct {
	binding Membership
	input   *fb.WGPathMemberContextT
	member  *fb.WGPathMemberContextT
}

// Registry binds runtime facts to independently resolved membership and current
// authenticated sessions. It owns no timer, sockets, policy or message sending.
// Its owner must serialize membership lifecycle and dispatch with coordinator
// operations; the snapshots returned here are not perpetual send authorization.
type Registry struct {
	mu       sync.Mutex
	edgeID   string
	members  MembershipReader
	controls types.CurrentClientSessionReader
	limits   RegistryLimits
	runtimes map[runtimeKey]*runtimeRecord
}

func NewRegistry(edgeID string, members MembershipReader, controls types.CurrentClientSessionReader, limits RegistryLimits) (*Registry, error) {
	if !validID(edgeID) || members == nil || controls == nil || limits.Members <= 0 {
		return nil, fmt.Errorf("invalid WG runtime registry dependencies/limits")
	}
	return &Registry{edgeID: edgeID, members: members, controls: controls, limits: limits,
		runtimes: make(map[runtimeKey]*runtimeRecord)}, nil
}

func networkAccess(identity types.SessionIdentity, networkID string) bool {
	if len(identity.ScopeClaims) == 0 {
		return true
	}
	for _, claim := range identity.ScopeClaims {
		if claim == "*" || claim == "network:"+networkID {
			return true
		}
	}
	return false
}

func (r *Registry) control(networkID, deviceID string) (types.SessionIdentity, error) {
	current, ok := r.controls.CurrentClientSession(deviceID)
	if !ok || !validID(current.SessionID) || current.DeviceID != deviceID {
		return types.SessionIdentity{}, fmt.Errorf("WG current authenticated control unavailable or outside network scope")
	}
	if !networkAccess(current, networkID) {
		return types.SessionIdentity{}, fmt.Errorf("%w: network scope", ErrCoordinationAccessRevoked)
	}
	for _, capability := range current.Capabilities {
		if capability == Capability {
			return current, nil
		}
	}
	return types.SessionIdentity{}, fmt.Errorf(
		"%w: device=%s hostname=%q session=%s does not advertise %s; capabilities=%v",
		ErrCoordinationAccessRevoked, deviceID, current.Hostname, current.SessionID, Capability, current.Capabilities)
}

func (r *Registry) authenticate(networkID string, sender types.SessionIdentity) error {
	current, err := r.control(networkID, sender.DeviceID)
	if err != nil {
		return err
	}
	if sender.SessionID != current.SessionID || sender.UserID != current.UserID {
		return fmt.Errorf("WG message is from a retired/different authenticated session")
	}
	return nil
}

func (r *Registry) validateNetwork(n NetworkBinding, networkID string) error {
	if n.CoordinatorID != r.edgeID {
		return fmt.Errorf("%w: network authority", ErrCoordinationAccessRevoked)
	}
	if n.NetworkID != networkID || !validID(networkID) ||
		n.PolicyRevision == 0 || n.RelayMode > fb.WGRelayModeFORCE ||
		(n.RelayPublicKey != "" && !validKey(n.RelayPublicKey)) {
		return fmt.Errorf("WG network registry authority/policy mismatch")
	}
	return nil
}

// AuthenticateMember supplies the limiter/request identity from real membership;
// unauthenticated messages cannot allocate owner limiter or pair records.
func (r *Registry) AuthenticateMember(networkID string, sender types.SessionIdentity) (Membership, error) {
	binding, err := r.Bootstrap(networkID, sender)
	return binding.Member, err
}

// Bootstrap requires current authentication/capability and membership, but no
// runtime report. It breaks the first-registration generation dependency without
// granting permission to allocate pairs or weakening Register's exact matching.
func (r *Registry) Bootstrap(networkID string, sender types.SessionIdentity) (MemberBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !validID(networkID) {
		return MemberBinding{}, fmt.Errorf("invalid WG network identity")
	}
	if err := r.authenticate(networkID, sender); err != nil {
		return MemberBinding{}, err
	}
	b, err := r.members.PathMember(networkID, sender.DeviceID)
	if err != nil {
		return MemberBinding{}, err
	}
	if err := r.validateNetwork(b.Network, networkID); err != nil {
		return MemberBinding{}, err
	}
	if b.Member.DeviceID != sender.DeviceID || !validID(b.Member.MemberID) || !validID(b.Member.Generation) {
		return MemberBinding{}, fmt.Errorf("WG authoritative member identity mismatch")
	}
	return b, nil
}

func sameMembership(a, b Membership) bool {
	return a.MemberID == b.MemberID && a.DeviceID == b.DeviceID && a.PublicKey == b.PublicKey &&
		a.AssignedIP == b.AssignedIP && a.Generation == b.Generation
}

func normalizeCandidates(candidates []*fb.WGPathCandidateT, fromRuntime bool) ([]*fb.WGPathCandidateT, error) {
	if len(candidates) > MaxCandidates {
		return nil, fmt.Errorf("too many WG endpoint candidates")
	}
	out := make([]*fb.WGPathCandidateT, 0, len(candidates))
	seen := make(map[string]bool)
	for _, candidate := range candidates {
		if candidate == nil || !validEndpoint(candidate.Endpoint) ||
			candidate.Kind < fb.WGPathCandidateKindLAN || candidate.Kind > fb.WGPathCandidateKindAUTHENTICATED_DIRECT ||
			(fromRuntime && candidate.Kind == fb.WGPathCandidateKindEDGE_OBSERVED) {
			return nil, fmt.Errorf("invalid or client-forged WG candidate source")
		}
		endpoint, _ := netip.ParseAddrPort(candidate.Endpoint)
		if endpoint.Addr().IsLoopback() || endpoint.Addr().IsLinkLocalUnicast() {
			return nil, fmt.Errorf("WG candidate cannot use loopback/link-local")
		}
		copy := *candidate
		copy.Endpoint = endpoint.String()
		key := fmt.Sprintf("%d:%s", copy.Kind, copy.Endpoint)
		if seen[key] {
			return nil, fmt.Errorf("duplicate WG endpoint candidate")
		}
		seen[key] = true
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Endpoint < out[j].Endpoint
	})
	return out, nil
}

// Timestamps describe observations, not candidate identity or a reachability
// ordering clock. Refreshing a timestamp alone must not invalidate a trial.
func sameCandidates(a, b []*fb.WGPathCandidateT) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Endpoint != b[i].Endpoint || a[i].Kind != b[i].Kind {
			return false
		}
	}
	return true
}

func mergeMember(binding Membership, input, previous *fb.WGPathMemberContextT) (*fb.WGPathMemberContextT, error) {
	m := cloneMember(input)
	if m == nil {
		// No runtime input yet (member hasn't registered); create minimal context
		// from binding identity. Runtime fields will be populated on registration.
		m = &fb.WGPathMemberContextT{}
	}
	m.MemberId, m.DeviceId, m.PublicKey, m.AssignedIp, m.MembershipGeneration =
		binding.MemberID, binding.DeviceID, binding.PublicKey, binding.AssignedIP, binding.Generation
	if binding.ObservedEndpoint != "" {
		m.Candidates = append(m.Candidates, &fb.WGPathCandidateT{Endpoint: binding.ObservedEndpoint,
			Kind: fb.WGPathCandidateKindEDGE_OBSERVED, ObservedAt: binding.ObservedAt})
	}
	var err error
	m.Candidates, err = normalizeCandidates(m.Candidates, false)
	if err != nil {
		return nil, err
	}
	m.CandidateRevision = 1 // Edge-owned merged revision, independent of client counter
	if previous != nil {
		m.CandidateRevision = previous.CandidateRevision
		if m.RuntimeGeneration != previous.RuntimeGeneration || m.NetworkEnvironment != previous.NetworkEnvironment ||
			!sameCandidates(m.Candidates, previous.Candidates) {
			if m.CandidateRevision == math.MaxUint64 {
				return nil, fmt.Errorf("WG merged candidate revision exhausted")
			}
			m.CandidateRevision++
		}
	}
	// Skip full ValidateMember when runtime fields are absent (member hasn't
	// registered yet). Identity fields are already bound from the authenticated
	// membership above. Full validation occurs once the member registers runtime.
	if m.RuntimeGeneration != "" && m.NetworkEnvironment != "" {
		if err := ValidateMember(m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Register accepts facts only from the current authenticated device connection.
// Membership identity fields are replaced from the Edge registry. Candidate
// revision guards against stale data within the same generation/environment.
func (r *Registry) Register(sender types.SessionIdentity, report *fb.WGPathRuntimeReportT) (*fb.WGPathMemberContextT, error) {
	if report == nil || report.Member == nil || !validID(report.NetworkId) || len(report.Member.Candidates) > MaxCandidates {
		return nil, fmt.Errorf("missing WG runtime report")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.authenticate(report.NetworkId, sender); err != nil {
		return nil, err
	}
	b, err := r.members.PathMember(report.NetworkId, sender.DeviceID)
	if err != nil {
		return nil, err
	}
	if err := r.validateNetwork(b.Network, report.NetworkId); err != nil {
		return nil, err
	}
	if b.Member.DeviceID != sender.DeviceID || (report.Member.MemberId != "" && report.Member.MemberId != b.Member.MemberID) ||
		report.Member.MembershipGeneration != b.Member.Generation {
		return nil, fmt.Errorf("WG runtime cannot report for another member")
	}
	input := cloneMember(report.Member)
	input.Candidates, err = normalizeCandidates(input.Candidates, true)
	if err != nil || input.CandidateRevision == 0 {
		return nil, fmt.Errorf("invalid WG runtime candidates/revision: %v", err)
	}
	key := runtimeKey{report.NetworkId, b.Member.MemberID}
	previous := r.runtimes[key]
	if previous != nil && !sameMembership(previous.binding, b.Member) {
		previous = nil // explicit identity/generation change revokes all old runtime facts
	}
	if previous == nil && r.runtimes[key] == nil && len(r.runtimes) >= r.limits.Members {
		return nil, fmt.Errorf("WG runtime registry member quota reached")
	}
	var oldMember *fb.WGPathMemberContextT
	rotation := false
	if previous != nil && previous.input != nil {
		oldMember = previous.member
		oldInput := previous.input
		rotation = input.RuntimeGeneration != oldInput.RuntimeGeneration || input.NetworkEnvironment != oldInput.NetworkEnvironment
		if !rotation && (input.CandidateRevision < oldInput.CandidateRevision ||
			(input.CandidateRevision == oldInput.CandidateRevision && !sameCandidates(input.Candidates, oldInput.Candidates))) {
			return nil, fmt.Errorf("stale/conflicting WG runtime candidate revision")
		}
	}
	member, err := mergeMember(b.Member, input, oldMember)
	if err != nil {
		return nil, err
	}
	// Commit only after all validation.
	if previous == nil {
		previous = &runtimeRecord{}
	}
	previous.binding, previous.input, previous.member = b.Member, input, member
	r.runtimes[key] = previous
	return cloneMember(member), nil
}

func (r *Registry) scope(pair PairKey) (Scope, error) {
	canonical, err := NewPairKey(pair.NetworkID, pair.MemberAID, pair.MemberBID)
	if err != nil || canonical != pair {
		return Scope{}, fmt.Errorf("invalid WG registry pair")
	}
	b, err := r.members.PathPair(pair)
	if err != nil {
		return Scope{}, err
	}
	if err := r.validateNetwork(b.Network, pair.NetworkID); err != nil {
		return Scope{}, err
	}
	s := Scope{Pair: pair, CoordinatorID: b.Network.CoordinatorID, PolicyRevision: b.Network.PolicyRevision,
		RelayMode: b.Network.RelayMode, RelayPublicKey: b.Network.RelayPublicKey}
	for i, id := range [2]string{pair.MemberAID, pair.MemberBID} {
		binding := b.Members[i]
		record := r.runtimes[runtimeKey{pair.NetworkID, id}]
		if binding.MemberID != id {
			return Scope{}, fmt.Errorf("WG member ID mismatch for member %s", id)
		}
		// Runtime registration is optional; use the same membership/session
		// checks whether or not this member has published runtime facts.
		var input, previous *fb.WGPathMemberContextT
		if record != nil {
			if !sameMembership(record.binding, binding) {
				return Scope{}, fmt.Errorf("WG runtime revoked for member %s", id)
			}
			input, previous = record.input, record.member
		}
		member, err := mergeMember(binding, input, previous)
		if err != nil {
			return Scope{}, err
		}
		s.Members[i] = member
		control, err := r.control(pair.NetworkID, binding.DeviceID)
		if err == nil {
			s.Sessions[i], s.Capable[i] = control.SessionID, true
		} else {
			// An offline control is not a revocation. A live session that lost
			// capability or network scope must fail explicitly.
			if _, online := r.controls.CurrentClientSession(binding.DeviceID); online {
				return Scope{}, err
			}
			s.Capable[i] = true
		}
	}
	// Validate the full pair (distinct keys/devices/IPs and valid relay identity)
	// without opening a transaction or allocating an authority epoch.
	probe := &Coordinator{edgeID: r.edgeID, epoch: "registry-validation"}
	if err := probe.validateScope(s); err != nil {
		return Scope{}, err
	}
	for i, id := range [2]string{pair.MemberAID, pair.MemberBID} {
		key := runtimeKey{pair.NetworkID, id}
		record := r.runtimes[key]
		if record != nil {
			record.binding, record.member = b.Members[i], cloneMember(s.Members[i])
		}
	}
	return s, nil
}

// Scope re-resolves current membership, policy and controls on every use.
func (r *Registry) Scope(pair PairKey) (Scope, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.scope(pair)
}

// Prune removes only records independently confirmed revoked/replaced by the
// membership authority. Reconnect, silence and age never evict replay history.
// A lookup failure may mean temporary source failure, so it is retained.
func (r *Registry) Prune() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	removed := 0
	for key, record := range r.runtimes {
		binding, err := r.members.PathMember(key.network, record.binding.DeviceID)
		if errors.Is(err, ErrMembershipRevoked) || (err == nil && !sameMembership(binding.Member, record.binding)) {
			delete(r.runtimes, key)
			removed++
		}
	}
	return removed
}
