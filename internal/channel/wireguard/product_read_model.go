package wireguard

import (
	"sort"
	"strings"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/wireguard/relay"
)

func toMillis(value time.Time) uint64 {
	if value.IsZero() {
		return 0
	}
	return uint64(value.UnixNano() / int64(time.Millisecond))
}

func mapRelayModeToFB(mode RelayMode) fbMsg.WGRelayMode {
	switch mode {
	case RelayModeDisabled:
		return fbMsg.WGRelayModeDISABLED
	case RelayModeForce:
		return fbMsg.WGRelayModeFORCE
	default:
		return fbMsg.WGRelayModeOPTIONAL
	}
}

func mapNetworkStatusToFB(status NetworkStatus) fbMsg.WGNetworkStatus {
	switch status {
	case NetworkStatusNew:
		return fbMsg.WGNetworkStatusNEW
	case NetworkStatusDeleting:
		return fbMsg.WGNetworkStatusDELETING
	case NetworkStatusDeleted:
		return fbMsg.WGNetworkStatusDELETED
	default:
		return fbMsg.WGNetworkStatusACTIVE
	}
}

func mapMemberMembershipStatusToFB(status MemberStatus) fbMsg.WGMemberMembershipStatus {
	switch status {
	case MemberStatusPending:
		return fbMsg.WGMemberMembershipStatusJOINING
	case MemberStatusRemoved:
		return fbMsg.WGMemberMembershipStatusREMOVED
	default:
		return fbMsg.WGMemberMembershipStatusACTIVE
	}
}

func mapMemberStatusToFB(member *NetworkMember) fbMsg.WGMemberStatus {
	if member == nil {
		return fbMsg.WGMemberStatusPENDING
	}
	if member.Status == MemberStatusRemoved {
		return fbMsg.WGMemberStatusREMOVED
	}
	if memberIsOnline(member) {
		return fbMsg.WGMemberStatusONLINE
	}
	if member.Status == MemberStatusPending {
		return fbMsg.WGMemberStatusPENDING
	}
	return fbMsg.WGMemberStatusACTIVE
}

// hasRealPublicKey 判断成员是否携带真实 WG 公钥。
// 设备 tab「+」代加的成员先以 clientId 占位公钥加入（见 handler.HandleJoinNetwork），
// 在其真正启动 WG 客户端、用真实公钥重新加入前不应被视为在线。
func hasRealPublicKey(m *NetworkMember) bool {
	if m == nil || m.PublicKey == "" || m.PublicKey == m.ClientID {
		return false
	}
	// Validate that the public key is a properly-formatted WireGuard key.
	// This filters out placeholder or malformed keys that would fail when
	// programming the WireGuard interface.
	if _, err := wgtypes.ParseKey(m.PublicKey); err != nil {
		return false
	}
	return true
}

// memberIsOnline 仅当成员状态为 Online 且携带真实公钥时才算真正在线。
// 这样既阻止代加占位成员显示为在线，也能自愈历史上被误置为 online 的占位成员
// （读模型层判定，无需改库内已持久化的状态）。
func memberIsOnline(m *NetworkMember) bool {
	return m != nil && m.Status == MemberStatusOnline && hasRealPublicKey(m)
}

func mapMemberPresence(m *NetworkMember) fbMsg.WGMemberPresenceStatus {
	if memberIsOnline(m) {
		return fbMsg.WGMemberPresenceStatusONLINE
	}
	if m != nil && m.Status == MemberStatusPending {
		return fbMsg.WGMemberPresenceStatusPRESENCE_UNKNOWN
	}
	return fbMsg.WGMemberPresenceStatusOFFLINE
}

func resolveObservedEndpointForSnapshot(_ *Network, member *NetworkMember, relayNode *relay.RelayNodeInfo) string {
	if member == nil {
		return ""
	}
	// observed_endpoint is always the UDP endpoint learned from the Edge WG
	// observation interface.  Relay mode changes the endpoint selected by the
	// client, but must not overwrite this field with Edge's relay address (or
	// with the mTLS control connection address).
	endpoint := strings.TrimSpace(member.Endpoint)
	if endpoint != "" {
		return endpoint
	}
	if member.IsRelay && relayNode != nil {
		return strings.TrimSpace(relayNode.Endpoint)
	}
	return ""
}

func relayEndpointForMember(relayNode *relay.RelayNodeInfo, member *NetworkMember) string {
	if relayNode == nil {
		return ""
	}
	return strings.TrimSpace(relayNode.Endpoint)
}

func relayFallbackAvailable(network *Network, relayNode *relay.RelayNodeInfo) bool {
	return networkUsesRelay(network) && relayNode != nil && relayNode.Endpoint != ""
}

func runtimeHealthForOverview(
	network *Network,
	members []*NetworkMember,
	relayNode *relay.RelayNodeInfo,
) fbMsg.WGNetworkRuntimeHealth {
	activeMembers := 0
	onlineMembers := 0
	for _, member := range members {
		if member == nil || member.Status == MemberStatusRemoved {
			continue
		}
		activeMembers++
		if memberIsOnline(member) {
			onlineMembers++
		}
	}
	if activeMembers == 0 || onlineMembers == 0 {
		return fbMsg.WGNetworkRuntimeHealthOFFLINE
	}
	return fbMsg.WGNetworkRuntimeHealthHEALTHY
}

func currentMemberForDevice(members []*NetworkMember, currentDeviceID string) *NetworkMember {
	if currentDeviceID == "" {
		return nil
	}
	for _, member := range members {
		if member == nil || member.Status == MemberStatusRemoved || member.Status == MemberStatusLeaved || !hasRealPublicKey(member) {
			continue
		}
		if member.ClientID == currentDeviceID {
			return member
		}
	}
	return nil
}

func buildWGNetworkSummaryOffset(
	builder *flatbuffers.Builder,
	network *Network,
	members []*NetworkMember,
	relayNode *relay.RelayNodeInfo,
	currentDeviceID string,
) flatbuffers.UOffsetT {
	networkIDOffset := builder.CreateString(network.ID)
	ownerUserIDOffset := builder.CreateString(network.OwnerUserID)
	nameOffset := builder.CreateString(network.Name)
	subnetOffset := builder.CreateString(network.CIDR)
	coordinatorEdgeIDOffset := builder.CreateString(network.CoordinatorEdgeID)
	currentMember := currentMemberForDevice(members, currentDeviceID)

	memberCount := uint32(0)
	onlineMemberCount := uint32(0)
	for _, member := range members {
		if member == nil || member.Status == MemberStatusRemoved || member.IsRelay {
			continue
		}
		memberCount++
		if memberIsOnline(member) {
			onlineMemberCount++
		}
	}

	fbMsg.WGNetworkSummaryInfoStart(builder)
	fbMsg.WGNetworkSummaryInfoAddNetworkId(builder, networkIDOffset)
	fbMsg.WGNetworkSummaryInfoAddOwnerUserId(builder, ownerUserIDOffset)
	fbMsg.WGNetworkSummaryInfoAddName(builder, nameOffset)
	fbMsg.WGNetworkSummaryInfoAddSubnet(builder, subnetOffset)
	fbMsg.WGNetworkSummaryInfoAddLifecycleStatus(builder, mapNetworkStatusToFB(network.Status))
	fbMsg.WGNetworkSummaryInfoAddRuntimeHealth(builder, runtimeHealthForOverview(network, members, relayNode))
	fbMsg.WGNetworkSummaryInfoAddMemberCount(builder, memberCount)
	fbMsg.WGNetworkSummaryInfoAddOnlineMemberCount(builder, onlineMemberCount)
	fbMsg.WGNetworkSummaryInfoAddSelfJoined(builder, currentMember != nil)
	fbMsg.WGNetworkSummaryInfoAddCreatedAt(builder, toMillis(network.CreatedAt))
	fbMsg.WGNetworkSummaryInfoAddUpdatedAt(builder, toMillis(network.UpdatedAt))
	fbMsg.WGNetworkSummaryInfoAddCoordinatorEdgeId(builder, coordinatorEdgeIDOffset)
	return fbMsg.WGNetworkSummaryInfoEnd(builder)
}

func buildWGNetworkDetailOffset(
	builder *flatbuffers.Builder,
	network *Network,
	members []*NetworkMember,
	relayNode *relay.RelayNodeInfo,
	currentClientID string,
) flatbuffers.UOffsetT {
	descriptionOffset := builder.CreateString("")
	currentMember := currentMemberForDevice(members, currentClientID)
	selfMemberIDOffset := builder.CreateString("")
	selfDeviceIDOffset := builder.CreateString("")
	if currentMember != nil {
		selfMemberIDOffset = builder.CreateString(currentMember.ID)
		// member.ClientID is the bare deviceID — use it directly.
		selfDeviceIDOffset = builder.CreateString(currentMember.ClientID)
	}

	memberCount := uint32(0)
	onlineMemberCount := uint32(0)
	for _, member := range members {
		if member == nil || member.Status == MemberStatusRemoved || member.IsRelay {
			continue
		}
		memberCount++
		if memberIsOnline(member) {
			onlineMemberCount++
		}
	}

	networkIDOffset := builder.CreateString(network.ID)
	ownerUserIDOffset := builder.CreateString(network.OwnerUserID)
	nameOffset := builder.CreateString(network.Name)
	subnetOffset := builder.CreateString(network.CIDR)
	coordinatorEdgeIDOffset := builder.CreateString(network.CoordinatorEdgeID)

	fbMsg.WGNetworkDetailInfoStart(builder)
	fbMsg.WGNetworkDetailInfoAddNetworkId(builder, networkIDOffset)
	fbMsg.WGNetworkDetailInfoAddOwnerUserId(builder, ownerUserIDOffset)
	fbMsg.WGNetworkDetailInfoAddName(builder, nameOffset)
	fbMsg.WGNetworkDetailInfoAddDescription(builder, descriptionOffset)
	fbMsg.WGNetworkDetailInfoAddSubnet(builder, subnetOffset)
	fbMsg.WGNetworkDetailInfoAddRelayMode(builder, mapRelayModeToFB(network.RelayMode))
	fbMsg.WGNetworkDetailInfoAddLifecycleStatus(builder, mapNetworkStatusToFB(network.Status))
	fbMsg.WGNetworkDetailInfoAddRuntimeHealth(builder, runtimeHealthForOverview(network, members, relayNode))
	fbMsg.WGNetworkDetailInfoAddSelfJoined(builder, currentMember != nil)
	fbMsg.WGNetworkDetailInfoAddSelfMemberId(builder, selfMemberIDOffset)
	fbMsg.WGNetworkDetailInfoAddSelfDeviceId(builder, selfDeviceIDOffset)
	fbMsg.WGNetworkDetailInfoAddMemberCount(builder, memberCount)
	fbMsg.WGNetworkDetailInfoAddOnlineMemberCount(builder, onlineMemberCount)
	fbMsg.WGNetworkDetailInfoAddCreatedAt(builder, toMillis(network.CreatedAt))
	fbMsg.WGNetworkDetailInfoAddUpdatedAt(builder, toMillis(network.UpdatedAt))
	fbMsg.WGNetworkDetailInfoAddCoordinatorEdgeId(builder, coordinatorEdgeIDOffset)
	return fbMsg.WGNetworkDetailInfoEnd(builder)
}

func buildWGNetworkMemberOffsets(
	builder *flatbuffers.Builder,
	network *Network,
	members []*NetworkMember,
	relayNode *relay.RelayNodeInfo,
	currentUserID string,
	currentDeviceID string,
) []flatbuffers.UOffsetT {
	sortedMembers := make([]*NetworkMember, 0, len(members))
	for _, member := range members {
		if member == nil || member.Status == MemberStatusRemoved {
			continue
		}
		sortedMembers = append(sortedMembers, member)
	}
	sort.SliceStable(sortedMembers, func(i, j int) bool {
		return sortedMembers[i].CreatedAt.Before(sortedMembers[j].CreatedAt)
	})

	offsets := make([]flatbuffers.UOffsetT, 0, len(sortedMembers))
	for _, member := range sortedMembers {
		memberIDOffset := builder.CreateString(member.ID)
		networkIDOffset := builder.CreateString(member.NetworkID)
		userIDOffset := builder.CreateString(currentUserID)
		// member.ClientID is the bare deviceID — send it directly.
		wireDeviceID := member.ClientID
		deviceIDOffset := builder.CreateString(wireDeviceID)
		hostnameOffset := builder.CreateString(member.HostName)
		assignedIPOffset := builder.CreateString(member.IP)
		publicKeyOffset := builder.CreateString(member.PublicKey)
		publicKeyFingerprintOffset := builder.CreateString(wireDeviceID)
		observedEndpointOffset := builder.CreateString(resolveObservedEndpointForSnapshot(network, member, relayNode))
		generationOffset := flatbuffers.UOffsetT(0)
		if network != nil && network.Status == NetworkStatusActive && hasRealPublicKey(member) {
			if identity, err := pathMembership(member); err == nil {
				generationOffset = builder.CreateString(identity.Generation)
			}
		}

		fbMsg.WGNetworkMemberInfoStart(builder)
		fbMsg.WGNetworkMemberInfoAddMemberId(builder, memberIDOffset)
		fbMsg.WGNetworkMemberInfoAddNetworkId(builder, networkIDOffset)
		fbMsg.WGNetworkMemberInfoAddUserId(builder, userIDOffset)
		fbMsg.WGNetworkMemberInfoAddDeviceId(builder, deviceIDOffset)
		fbMsg.WGNetworkMemberInfoAddHostname(builder, hostnameOffset)
		fbMsg.WGNetworkMemberInfoAddAssignedIp(builder, assignedIPOffset)
		fbMsg.WGNetworkMemberInfoAddPublicKey(builder, publicKeyOffset)
		fbMsg.WGNetworkMemberInfoAddPublicKeyFingerprint(builder, publicKeyFingerprintOffset)
		fbMsg.WGNetworkMemberInfoAddMembershipStatus(builder, mapMemberMembershipStatusToFB(member.Status))
		fbMsg.WGNetworkMemberInfoAddPresenceStatus(builder, mapMemberPresence(member))
		fbMsg.WGNetworkMemberInfoAddIsCurrentDevice(builder, currentDeviceID != "" && member.ClientID == currentDeviceID)
		fbMsg.WGNetworkMemberInfoAddJoinedAt(builder, toMillis(member.CreatedAt))
		fbMsg.WGNetworkMemberInfoAddLastSeenAt(builder, toMillis(member.LastOnline))
		fbMsg.WGNetworkMemberInfoAddUpdatedAt(builder, toMillis(member.UpdatedAt))
		fbMsg.WGNetworkMemberInfoAddIsRelayNode(builder, member.IsRelay)
		fbMsg.WGNetworkMemberInfoAddObservedEndpoint(builder, observedEndpointOffset)
		fbMsg.WGNetworkMemberInfoAddObservedAt(builder, toMillis(member.ObservedAt))
		if generationOffset != 0 {
			fbMsg.WGNetworkMemberInfoAddMembershipGeneration(builder, generationOffset)
		}
		offsets = append(offsets, fbMsg.WGNetworkMemberInfoEnd(builder))
	}
	return offsets
}

func buildWGRelayNodeOffset(builder *flatbuffers.Builder, info *relay.RelayNodeInfo) flatbuffers.UOffsetT {
	if info == nil {
		return 0
	}
	memberIDOffset := builder.CreateString(info.MemberID)
	publicKeyOffset := builder.CreateString(info.PublicKey)
	endpointOffset := builder.CreateString(info.Endpoint)
	assignedIPOffset := builder.CreateString(info.AssignedIP)
	peerEndpointOffsets := make([]flatbuffers.UOffsetT, 0, len(info.PeerEndpoints))
	for _, peer := range info.PeerEndpoints {
		publicKeyOffset := builder.CreateString(peer.PublicKey)
		assignedIPOffset := builder.CreateString(peer.AssignedIP)
		endpointOffset := builder.CreateString(peer.Endpoint)
		fbMsg.WGRelayPeerEndpointInfoStart(builder)
		fbMsg.WGRelayPeerEndpointInfoAddPublicKey(builder, publicKeyOffset)
		fbMsg.WGRelayPeerEndpointInfoAddAssignedIp(builder, assignedIPOffset)
		fbMsg.WGRelayPeerEndpointInfoAddEndpoint(builder, endpointOffset)
		fbMsg.WGRelayPeerEndpointInfoAddListenPort(builder, uint32(peer.ListenPort))
		peerEndpointOffsets = append(peerEndpointOffsets, fbMsg.WGRelayPeerEndpointInfoEnd(builder))
	}
	fbMsg.WGRelayNodeInfoStartPeerEndpointsVector(builder, len(peerEndpointOffsets))
	for i := len(peerEndpointOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(peerEndpointOffsets[i])
	}
	peerEndpointsOffset := builder.EndVector(len(peerEndpointOffsets))

	fbMsg.WGRelayNodeInfoStart(builder)
	fbMsg.WGRelayNodeInfoAddMemberId(builder, memberIDOffset)
	fbMsg.WGRelayNodeInfoAddPublicKey(builder, publicKeyOffset)
	fbMsg.WGRelayNodeInfoAddEndpoint(builder, endpointOffset)
	fbMsg.WGRelayNodeInfoAddAssignedIp(builder, assignedIPOffset)
	fbMsg.WGRelayNodeInfoAddListenPort(builder, uint32(info.ListenPort))
	fbMsg.WGRelayNodeInfoAddPeerEndpoints(builder, peerEndpointsOffset)
	return fbMsg.WGRelayNodeInfoEnd(builder)
}

func buildWGNetworkRuntimeSnapshotOffset(
	builder *flatbuffers.Builder,
	overview *NetworkOverview,
	currentUserID string,
	currentDeviceID string,
) flatbuffers.UOffsetT {
	// member.ClientID is the bare deviceID set at JoinNetwork.
	// Use it directly for internal comparisons.
	fullClientID := currentDeviceID

	networkOffset := buildWGNetworkDetailOffset(
		builder,
		overview.Network,
		overview.Members,
		overview.RelayNode,
		fullClientID,
	)

	memberOffsets := buildWGNetworkMemberOffsets(builder, overview.Network, overview.Members, overview.RelayNode, currentUserID, fullClientID)
	fbMsg.WGNetworkRuntimeSnapshotInfoStartMembersVector(builder, len(memberOffsets))
	for i := len(memberOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(memberOffsets[i])
	}
	membersVectorOffset := builder.EndVector(len(memberOffsets))

	// peer_sessions is always empty: old PeerSession mechanism removed.
	fbMsg.WGNetworkRuntimeSnapshotInfoStartPeerSessionsVector(builder, 0)
	peerSessionsVectorOffset := builder.EndVector(0)

	relayNodeOffset := buildWGRelayNodeOffset(builder, overview.RelayNode)
	edgePublicEndpointOffset := flatbuffers.UOffsetT(0)
	if ep := strings.TrimSpace(overview.EdgePublicEndpoint); ep != "" {
		edgePublicEndpointOffset = builder.CreateString(ep)
	}

	// Build LAN peer endpoints vector.
	lanPeerEndpointsOffset := buildLANPeerEndpointsOffset(builder, overview.LANPeerEndpoints)
	epochOffset := flatbuffers.UOffsetT(0)
	if overview.PathAuthorityEpoch != "" {
		epochOffset = builder.CreateString(overview.PathAuthorityEpoch)
	}
	revisionEpochOffset := flatbuffers.UOffsetT(0)
	if overview.RevisionEpoch != "" {
		revisionEpochOffset = builder.CreateString(overview.RevisionEpoch)
	}
	var pathPairsOffset flatbuffers.UOffsetT
	if epochOffset != 0 && len(overview.PathPairs) > 0 {
		offsets := make([]flatbuffers.UOffsetT, 0, len(overview.PathPairs))
		for _, pair := range overview.PathPairs {
			offsets = append(offsets, pair.Pack(builder))
		}
		fbMsg.WGNetworkRuntimeSnapshotInfoStartPathPairsVector(builder, len(offsets))
		for i := len(offsets) - 1; i >= 0; i-- {
			builder.PrependUOffsetT(offsets[i])
		}
		pathPairsOffset = builder.EndVector(len(offsets))
	}

	fbMsg.WGNetworkRuntimeSnapshotInfoStart(builder)
	fbMsg.WGNetworkRuntimeSnapshotInfoAddNetwork(builder, networkOffset)
	fbMsg.WGNetworkRuntimeSnapshotInfoAddMembers(builder, membersVectorOffset)
	fbMsg.WGNetworkRuntimeSnapshotInfoAddPeerSessions(builder, peerSessionsVectorOffset)
	if relayNodeOffset != 0 {
		fbMsg.WGNetworkRuntimeSnapshotInfoAddRelayNode(builder, relayNodeOffset)
	}
	if edgePublicEndpointOffset != 0 {
		fbMsg.WGNetworkRuntimeSnapshotInfoAddEdgePublicEndpoint(builder, edgePublicEndpointOffset)
	}
	if lanPeerEndpointsOffset != 0 {
		fbMsg.WGNetworkRuntimeSnapshotInfoAddLanPeerEndpoints(builder, lanPeerEndpointsOffset)
	}
	fbMsg.WGNetworkRuntimeSnapshotInfoAddRevision(builder, overview.Revision)
	fbMsg.WGNetworkRuntimeSnapshotInfoAddCollectedAt(builder, uint64(time.Now().UnixNano()/int64(time.Millisecond)))
	// Policy is a public network fact, independent of recipient bootstrap.
	// Omitting it from shared progress pushes makes an unchanged policy look
	// revoked to clients and tears down their in-flight READY/APPLIED executor.
	fbMsg.WGNetworkRuntimeSnapshotInfoAddNetworkPolicyRevision(builder, overview.Network.pathPolicyRevision)
	if epochOffset != 0 {
		if pathPairsOffset != 0 {
			fbMsg.WGNetworkRuntimeSnapshotInfoAddPathPairs(builder, pathPairsOffset)
		}
		fbMsg.WGNetworkRuntimeSnapshotInfoAddPathAuthorityEpoch(builder, epochOffset)
	}
	if revisionEpochOffset != 0 {
		fbMsg.WGNetworkRuntimeSnapshotInfoAddRevisionEpoch(builder, revisionEpochOffset)
	}
	return fbMsg.WGNetworkRuntimeSnapshotInfoEnd(builder)
}

// buildLANPeerEndpointsOffset serializes the LAN peer endpoints map into a
// FlatBuffers vector of WGLANPeerEndpoint tables.  Each entry includes the
// first candidate (backward compat `lan_endpoint`) and all candidates
// (`lan_endpoint_candidates`).  Returns 0 if the map is empty.
func buildLANPeerEndpointsOffset(builder *flatbuffers.Builder, lanEndpoints map[string][]string) flatbuffers.UOffsetT {
	if len(lanEndpoints) == 0 {
		return 0
	}
	// Collect keys for deterministic ordering.
	keys := make([]string, 0, len(lanEndpoints))
	for k := range lanEndpoints {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	offsets := make([]flatbuffers.UOffsetT, 0, len(keys))
	for _, pubKey := range keys {
		candidates := lanEndpoints[pubKey]
		if len(candidates) == 0 {
			continue
		}
		pkOffset := builder.CreateString(pubKey)
		epOffset := builder.CreateString(candidates[0]) // backward compat: first candidate
		// Build candidates vector.
		var candidatesOffset flatbuffers.UOffsetT
		if len(candidates) > 1 {
			candidateOffsets := make([]flatbuffers.UOffsetT, len(candidates))
			for j := len(candidates) - 1; j >= 0; j-- {
				candidateOffsets[j] = builder.CreateString(candidates[j])
			}
			fbMsg.WGLANPeerEndpointStartLanEndpointCandidatesVector(builder, len(candidates))
			for _, co := range candidateOffsets {
				builder.PrependUOffsetT(co)
			}
			candidatesOffset = builder.EndVector(len(candidates))
		}
		fbMsg.WGLANPeerEndpointStart(builder)
		fbMsg.WGLANPeerEndpointAddPublicKey(builder, pkOffset)
		fbMsg.WGLANPeerEndpointAddLanEndpoint(builder, epOffset)
		fbMsg.WGLANPeerEndpointAddLanEndpointCandidates(builder, candidatesOffset)
		offsets = append(offsets, fbMsg.WGLANPeerEndpointEnd(builder))
	}
	if len(offsets) == 0 {
		return 0
	}
	fbMsg.WGNetworkRuntimeSnapshotInfoStartLanPeerEndpointsVector(builder, len(offsets))
	for i := len(offsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(offsets[i])
	}
	return builder.EndVector(len(offsets))
}
