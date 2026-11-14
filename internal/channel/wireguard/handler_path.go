package wireguard

import (
	"fmt"
	"reflect"
	"time"

	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/internal/channel/wireguard/pathcoord"
	logger "icool.io/yat/edge/pkg/log"
)

// PathControlReceiver is the narrow owner ingress.
// HandlePathControl dispatches by message type internally.
type PathControlReceiver interface {
	HandlePathControl(types.SessionIdentity, pathcoord.ControlMessage) error
}

var _ PathControlReceiver = (*pathcoord.Owner)(nil)

type pathBootstrapReader interface {
	Bootstrap(string, types.SessionIdentity) (pathcoord.BootstrapContext, error)
}

type pathRuntimePairsReader interface {
	RuntimePairs(string, types.SessionIdentity, time.Time) ([]*fb.WGPathPairRuntimeInfoT, error)
}

// withPathBootstrap enriches an authenticated response only when its copied
// membership/policy still matches the gated owner's current registry. Ordinary
// broadcasts and a missing/stopped owner never fabricate a coordination epoch.
func (h *WireGuardHandler) withPathBootstrap(ctx HandlerSession, overview *NetworkOverview) *NetworkOverview {
	result, err := h.withPathBootstrapResult(ctx, overview)
	if err != nil {
		logger.Debugf("[PathBootstrap] device=%s session=%s: %v", ctx.DeviceID, ctx.SessionID, err)
	}
	return result
}

// Runtime reads must preserve bootstrap failures for coordinating clients.
// Returning an ordinary successful snapshot here hides revoked membership or
// a retired session behind an empty epoch, leaving responders unable to reply.
func (h *WireGuardHandler) withPathBootstrapResult(ctx HandlerSession, overview *NetworkOverview) (*NetworkOverview, error) {
	if overview == nil {
		return nil, fmt.Errorf("WG bootstrap network overview unavailable")
	}
	copy := *overview
	copy.PathAuthorityEpoch = ""
	copy.PathPairs = nil
	if overview.Network == nil || ctx.DeviceID == "" || ctx.SessionID == "" {
		logger.Debugf("[PathBootstrap] early return: network=%v conn=%v deviceID=%q sessionID=%q",
			overview.Network != nil, ctx.Conn != nil, ctx.DeviceID, ctx.SessionID)
		return &copy, fmt.Errorf("WG bootstrap requires an authenticated network session")
	}
	h.pathControlMu.RLock()
	reader, ok := h.pathControl.(pathBootstrapReader)
	h.pathControlMu.RUnlock()
	if !ok {
		logger.Debugf("[PathBootstrap] pathControl does not implement pathBootstrapReader, network=%s", overview.Network.ID)
		return &copy, nil // Legacy Edge: no coordination owner was configured.
	}
	b, err := reader.Bootstrap(overview.Network.ID, pathSessionIdentity(ctx))
	if err != nil {
		return &copy, fmt.Errorf("WG path bootstrap rejected: %w", err)
	}
	if b.AuthorityEpoch == "" {
		return &copy, fmt.Errorf("WG path bootstrap authority epoch unavailable")
	}
	n := overview.Network
	if b.Binding.Network.NetworkID != n.ID || b.Binding.Network.CoordinatorID != n.CoordinatorEdgeID ||
		b.Binding.Network.PolicyRevision != n.pathPolicyRevision || b.Binding.Network.RelayMode != mapRelayModeToFB(n.RelayMode) {
		logger.Debugf("[PathBootstrap] binding mismatch: network=%s binding=(id=%s coord=%s rev=%d relay=%s) actual=(id=%s coord=%s rev=%d relay=%s)",
			n.ID, b.Binding.Network.NetworkID, b.Binding.Network.CoordinatorID, b.Binding.Network.PolicyRevision, b.Binding.Network.RelayMode,
			n.ID, n.CoordinatorEdgeID, n.pathPolicyRevision, mapRelayModeToFB(n.RelayMode))
		return &copy, fmt.Errorf("WG path bootstrap network policy changed during read")
	}
	if b.Binding.Network.RelayPublicKey != "" && (overview.RelayNode == nil ||
		overview.RelayNode.PublicKey != b.Binding.Network.RelayPublicKey) {
		logger.Debugf("[PathBootstrap] relay public key mismatch: network=%s", n.ID)
		return &copy, fmt.Errorf("WG path bootstrap relay identity changed during read")
	}
	for _, m := range overview.Members {
		if m == nil || m.ID != b.Binding.Member.MemberID {
			continue
		}
		identity, err := pathMembership(m)
		if err == nil && identity.MemberID == b.Binding.Member.MemberID && identity.DeviceID == b.Binding.Member.DeviceID &&
			identity.PublicKey == b.Binding.Member.PublicKey && identity.AssignedIP == b.Binding.Member.AssignedIP &&
			identity.Generation == b.Binding.Member.Generation {
			copy.PathAuthorityEpoch = b.AuthorityEpoch
			if pairsReader, ok := reader.(pathRuntimePairsReader); ok {
				pairs, err := pairsReader.RuntimePairs(n.ID, pathSessionIdentity(ctx), time.Now())
				if err == nil {
					for _, pair := range pairs {
						if pair != nil && pair.Plan != nil && pair.Plan.Version != nil && pair.Plan.Version.AuthorityEpoch == b.AuthorityEpoch &&
							pair.Plan.Version.NetworkPolicyRevision == n.pathPolicyRevision && pathPairMatchesOverview(pair.Plan, overview) {
							copy.PathPairs = append(copy.PathPairs, pair)
						}
					}
				} else {
					logger.Debugf("[PathBootstrap] RuntimePairs failed: network=%s err=%v", n.ID, err)
					copy.PathAuthorityEpoch = ""
					return &copy, fmt.Errorf("WG path pair snapshot rejected: %w", err)
				}
			}
		} else {
			logger.Debugf("[PathBootstrap] member mismatch: network=%s member=%s binding=(id=%s device=%s) actual=(id=%s device=%s err=%v)",
				n.ID, m.ID, b.Binding.Member.MemberID, b.Binding.Member.DeviceID, identity.MemberID, identity.DeviceID, err)
		}
		if copy.PathAuthorityEpoch == "" {
			return &copy, fmt.Errorf("WG path bootstrap member identity changed during read")
		}
		return &copy, nil
	}
	return &copy, fmt.Errorf("WG path bootstrap self member absent from snapshot")
}

func pathPairMatchesOverview(plan *fb.WGPathPlanT, overview *NetworkOverview) bool {
	for _, expected := range []*fb.WGPathMemberContextT{plan.MemberA, plan.MemberB} {
		if expected == nil {
			return false
		}
		found := false
		for _, member := range overview.Members {
			if member == nil || member.ID != expected.MemberId {
				continue
			}
			actual, err := pathMembership(member)
			found = err == nil && actual.DeviceID == expected.DeviceId && actual.PublicKey == expected.PublicKey &&
				actual.AssignedIP == expected.AssignedIp && actual.Generation == expected.MembershipGeneration
			break
		}
		if !found {
			return false
		}
	}
	return true
}

func pathSessionIdentity(ctx HandlerSession) types.SessionIdentity {
	return types.SessionIdentity{SessionID: ctx.SessionID, UserID: ctx.UserID,
		DeviceID: ctx.DeviceID, Hostname: ctx.Hostname, Capabilities: append([]string(nil), ctx.Capabilities...),
		ScopeClaims: append([]string(nil), ctx.ScopeClaims...)}
}

// AttachPathControlReceiver is construction-time wiring, not capability
// publication or scheduler enablement. Explicit production assembly uses a
// ManagedOnly owner so bootstrap/ingress stay closed until takeover completes.
func (h *WireGuardHandler) AttachPathControlReceiver(receiver PathControlReceiver) error {
	h.pathControlMu.Lock()
	defer h.pathControlMu.Unlock()
	if receiver == nil || h.pathControl != nil {
		return fmt.Errorf("WG path control receiver missing or already attached")
	}
	h.pathControl = receiver
	return nil
}

func (h *WireGuardHandler) HandlePathControl(ctx HandlerSession, message *fb.Message) error {
	h.pathControlMu.RLock()
	receiver := h.pathControl
	h.pathControlMu.RUnlock()
	if receiver == nil {
		logger.Debugf("[PathControl] HandlePathControl: receiver is nil (coordination not enabled)")
		return fmt.Errorf("WG path coordination is not enabled")
	}
	if ctx.Conn == nil || ctx.DeviceID == "" || ctx.SessionID == "" {
		logger.Debugf("[PathControl] HandlePathControl: missing auth context conn=%v deviceID=%q sessionID=%q",
			ctx.Conn != nil, ctx.DeviceID, ctx.SessionID)
		return fmt.Errorf("WG path control requires an authenticated connection")
	}
	decoded, err := pathcoord.DecodeControl(message)
	if err != nil {
		logger.Debugf("[PathControl] HandlePathControl: decode error: %v", err)
		return err
	}
	logger.Infof("[PathControl] HandlePathControl: device=%s session=%s msgType=%v",
		ctx.DeviceID, ctx.SessionID, message.Header(nil).Type())
	sender := pathSessionIdentity(ctx)
	network := ""
	if decoded.Request != nil {
		network = decoded.Request.NetworkId
	}
	if decoded.Report != nil && decoded.Report.Version != nil {
		network = decoded.Report.Version.NetworkId
	}
	var before []*fb.WGPathPairRuntimeInfoT
	reader, observable := receiver.(pathRuntimePairsReader)
	if observable && network != "" {
		before, _ = reader.RuntimePairs(network, sender, time.Now())
	}
	err = receiver.HandlePathControl(sender, decoded)
	// Publish outside Owner's lock. Duplicate reports do not create an event loop.
	if observable && network != "" {
		after, readErr := reader.RuntimePairs(network, sender, time.Now())
		if readErr == nil {
			if members := changedPathMembers(before, after); len(members) > 0 {
				_ = h.pushNetworkEvent(network, fb.WGNetworkEventActionRUNTIME_UPDATE, members)
			}
		}
	}
	if err == nil && decoded.Request != nil && message.Header(nil).Seq() != 0 {
		return h.sendNetworkRuntimeResponse(ctx, network, message.Header(nil).Seq())
	}
	return err
}

func changedPathMembers(before, after []*fb.WGPathPairRuntimeInfoT) map[string]struct{} {
	index := func(pairs []*fb.WGPathPairRuntimeInfoT) map[[2]string]*fb.WGPathPairRuntimeInfoT {
		result := make(map[[2]string]*fb.WGPathPairRuntimeInfoT, len(pairs))
		for _, pair := range pairs {
			if pair != nil && pair.Plan != nil && pair.Plan.Version != nil {
				v := pair.Plan.Version
				result[[2]string{v.MemberAId, v.MemberBId}] = pair
			}
		}
		return result
	}
	old, current := index(before), index(after)
	members := make(map[string]struct{})
	add := func(key [2]string) {
		for _, id := range key {
			if id != "" {
				members[id] = struct{}{}
			}
		}
	}
	for key, pair := range current {
		if !reflect.DeepEqual(old[key], pair) {
			add(key)
		}
	}
	for key := range old {
		if _, exists := current[key]; !exists {
			add(key)
		}
	}
	return members
}
