package wireguard

import "icool.io/yat/edge/internal/channel/types"

// MembersWithControlPresence returns read-model copies. Client presence means
// a current authenticated session with network access, independent of the WG
// relay's handshake observations. It grants no path capability or membership.
// The coordinator's observer state and persisted registration remain unchanged.
func MembersWithControlPresence(members []*NetworkMember, controls types.CurrentClientSessionReader) []*NetworkMember {
	if members == nil {
		return nil
	}
	result := make([]*NetworkMember, 0, len(members))
	for _, member := range members {
		if member == nil {
			continue
		}
		copy := *member
		copy.LANEndpointCandidates = append([]string(nil), member.LANEndpointCandidates...)
		if controls != nil && !copy.IsRelay && (copy.Status == MemberStatusActive || copy.Status == MemberStatusOnline) {
			copy.Status = MemberStatusActive
			if !copy.pathRevoked && hasRealPublicKey(&copy) {
				identity, ok := controls.CurrentClientSession(copy.ClientID)
				if ok && identity.SessionID != "" && identity.DeviceID == copy.ClientID &&
					hasNetworkAccess(HandlerSession{ScopeClaims: identity.ScopeClaims}, copy.NetworkID) {
					copy.Status = MemberStatusOnline
				}
			}
		}
		result = append(result, &copy)
	}
	return result
}

// Every product read/push uses the same current-session source. Do not write
// this projected status back into the coordinator's relay observation state.
func (h *WireGuardHandler) getNetworkOverview(networkID string) (*NetworkOverview, error) {
	overview, err := h.coordinator.GetNetworkOverview(networkID)
	if err != nil || overview == nil {
		return overview, err
	}
	controls, ok := h.sessions.(types.CurrentClientSessionReader)
	if !ok {
		return overview, nil // Compatibility with legacy session providers.
	}
	copy := *overview
	copy.Members = MembersWithControlPresence(overview.Members, controls)
	return &copy, nil
}
