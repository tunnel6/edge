package wireguard

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/uuid"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	p2p "icool.io/yat/edge/internal/channel/p2p"
	"icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/internal/channel/wireguard/pathcoord"
	"icool.io/yat/edge/internal/channel/wireguard/relay"
	logger "icool.io/yat/edge/pkg/log"
)

// HandlerSession carries the per-request session identity and connection
// for WireGuard handlers.  It is a plain value struct (not an interface)
// to avoid name collisions between Go promoted fields and methods.
// Constructed in proxy_setup.go from channel.HandlerContext.
type HandlerSession struct {
	SessionID    string
	UserID       string
	DeviceID     string
	Hostname     string
	Capabilities []string
	ScopeClaims  []string // Certificate scope claims (nil = full access)
	Conn         net.Conn
}

// Handle
type WireGuardHandler struct {
	coordinator     HandlerCoordinator
	sessions        ClientPusher
	p2pCoordinator  *p2p.Coordinator
	edgeID          string
	deviceLister    OnlineDeviceLister
	inviteStore     *InviteStore
	pathControlMu   sync.RWMutex
	pathControl     PathControlReceiver // nil until gated owner/legacy exclusion is installed
	runtimeVersions runtimeVersionClock
}

// runtimeVersionClock gives snapshots and invalidation events one Edge-owned
// order. It deliberately stores no network or path negotiation state: the
// per-network counter only versions accepted read-model publications.
type runtimeVersionClock struct {
	mu       sync.Mutex
	epoch    string
	networks map[string]*runtimeNetworkVersion
}

type runtimeNetworkVersion struct {
	mu       sync.Mutex
	revision uint64
}

func (c *runtimeVersionClock) network(networkID string) (*runtimeNetworkVersion, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.epoch == "" {
		c.epoch = uuid.NewString()
	}
	if c.networks == nil {
		c.networks = make(map[string]*runtimeNetworkVersion)
	}
	state := c.networks[networkID]
	if state == nil {
		state = &runtimeNetworkVersion{}
		c.networks[networkID] = state
	}
	return state, c.epoch
}

func (c *runtimeVersionClock) advanceLocked(state *runtimeNetworkVersion) (uint64, error) {
	if state.revision == ^uint64(0) {
		return 0, fmt.Errorf("WG runtime revision exhausted")
	}
	state.revision++
	return state.revision, nil
}

// getVersionedNetworkOverview reads the Edge projection and its current
// sequencer position under the same per-network publication lock used by
// pushes. A caller must not substitute client timestamps or local counters.
func (h *WireGuardHandler) getVersionedNetworkOverview(networkID string) (*NetworkOverview, error) {
	state, epoch := h.runtimeVersions.network(networkID)
	state.mu.Lock()
	defer state.mu.Unlock()
	overview, err := h.getNetworkOverview(networkID)
	if err != nil || overview == nil {
		return overview, err
	}
	versioned := *overview
	versioned.RevisionEpoch = epoch
	versioned.Revision = state.revision
	return &versioned, nil
}

// OnlineDeviceLister 枚举某用户当前在线设备（由 server.SessionManager 实现）。
type OnlineDeviceLister interface {
	ListOnlineDevicesByUser(userID string) []OnlineDeviceInfo
}

// OnlineDeviceInfo 镜像 channel/types.OnlineDevice，避免 wireguard 包反向依赖。
type OnlineDeviceInfo struct {
	ClientID   string
	DeviceID   string
	Hostname   string
	LastActive int64
}

type HandlerCoordinator interface {
	CreateNetworkWithRelay(req *CreateNetworkRequest) (*Network, *relay.RelayNodeInfo, error)
	JoinNetwork(req *JoinNetworkRequest) (*NetworkMember, error)
	SetMemberOnline(memberID string) error
	SetMemberOffline(memberID string) error
	SetMemberDisconnected(memberID string) error
	SetMemberOnlineByPublicKey(networkID, publicKey string) (error, bool)
	RemoveMember(memberID string) error
	DeleteNetwork(networkID string) error
	ListNetworks() []*Network
	GetNetworkOverview(networkID string) (*NetworkOverview, error)
	GetClientMember(clientID, networkID string) (*NetworkMember, error)
	GetNetwork(networkID string) (*Network, error)
	NotifyRelayPeerLeft(networkID, publicKey string)
	UpdateNetworkCIDR(networkID, newCIDR string) error
	UpdateRelayMode(networkID string, mode RelayMode) error
	UpdateMemberIP(memberID, newIP string) error
	UpdateMember(memberID, newIP, newHostname string) error
	SuggestCIDRs(existingCIDRs []string) []string
	StoreLANEndpoint(networkID, publicKey string, candidates []string) bool
	GetLANPeerEndpointsForClient(networkID, requesterPublicKey string) map[string]string
	GetLANPeerEndpointCandidatesForClient(networkID, requesterPublicKey string) map[string][]string
	ListNetworkMembers(networkID string) []*NetworkMember
}

// Interface
type ClientPusher interface {
	PushToClient(clientID string, data []byte) error
	// AsyncPushToClients publishes data via the async ring-buffer broadcaster.
	// Only sessions whose DeviceID is in targetClients receive the message.
	AsyncPushToClients(targetClients []string, data []byte)
}

type clientSessionChecker interface {
	HasClientSession(clientID string) bool
}

// Handle
func NewWireGuardHandler(
	coordinator HandlerCoordinator,
	sessions ClientPusher,
	p2pCoordinator *p2p.Coordinator,
	edgeID string,
	deviceLister OnlineDeviceLister,
) *WireGuardHandler {
	handler := &WireGuardHandler{
		coordinator:    coordinator,
		sessions:       sessions,
		p2pCoordinator: p2pCoordinator,
		edgeID:         edgeID,
		deviceLister:   deviceLister,
		inviteStore:    NewInviteStore(),
	}
	// Direct reachability is decided by each client's WireGuard handshake
	// state.  Do not create the legacy gather/punch scheduler here: clients
	// no longer implement the WG_GATHER_INFO/WG_PUNCH_INFO exchange, so an
	// automatically-created session would remain in `gathering` until timeout
	// (and optional mode would keep recreating it).
	return handler
}

// GetInviteStore returns the handler's invite store for external wiring
// (e.g. connecting the Server's cert request flow to invite validation).
func (h *WireGuardHandler) GetInviteStore() *InviteStore {
	return h.inviteStore
}

// Get
func getNowMillis() int64 {
	return time.Now().UnixNano() / 1e6
}

// isNetworkOwnerOrMember reports whether the caller (identified by ctx)
// is the network owner or an existing member.  Used to gate read access
// to network details and runtime snapshots.
func (h *WireGuardHandler) isNetworkOwnerOrMember(ctx HandlerSession, network *Network) bool {
	if network == nil {
		return false
	}
	// Owner check
	if network.OwnerUserID != "" && ctx.UserID != "" && network.OwnerUserID == ctx.UserID {
		return true
	}
	// Member check: look up by deviceID
	if ctx.DeviceID != "" {
		if m, err := h.coordinator.GetClientMember(ctx.DeviceID, network.ID); err == nil && m != nil && m.Status != MemberStatusRemoved {
			return true
		}
	}
	return false
}

// hasNetworkAccess checks whether the session's certificate scope claims
// allow access to the given network. Returns true when:
//   - ScopeClaims is nil/empty (no restriction = full access), OR
//   - ScopeClaims contains "*" (explicit full access), OR
//   - ScopeClaims contains "network:<networkID>".
//
// This is a stateless check — the scope claims are embedded in the
// client's mTLS certificate and extracted at connection time.
func hasNetworkAccess(ctx HandlerSession, networkID string) bool {
	if len(ctx.ScopeClaims) == 0 {
		return true // No scope restriction = full access (backward compatible)
	}
	for _, claim := range ctx.ScopeClaims {
		if claim == "*" || claim == "network:"+networkID {
			return true
		}
	}
	return false
}

// hasExplicitNetworkScope reports whether the session's mTLS certificate
// carries an EXPLICIT scope granting access to networkID ("*" or
// "network:<networkID>").
//
// Unlike hasNetworkAccess, an empty ScopeClaims set is NOT treated as full
// access. This stricter variant gates whether a join may skip invite-token
// validation: the "network:<id>" scope is only embedded in a certificate at
// bootstrap after the invite token was validated (see server/tls.go), so it is
// a durable authorization grant that survives restarts. An unscoped certificate
// on a first join must still present a token.
func hasExplicitNetworkScope(ctx HandlerSession, networkID string) bool {
	for _, claim := range ctx.ScopeClaims {
		if claim == "*" || claim == "network:"+networkID {
			return true
		}
	}
	return false
}

// isActiveMember reports whether the device already holds a membership in the
// network that is neither removed nor soft-left. Used to let a restarting
// member re-join (the JoinNetwork handler is idempotent — it upgrades the
// public key in place) without re-presenting the single-use invite token.
func (h *WireGuardHandler) isActiveMember(deviceID, networkID string) bool {
	if deviceID == "" {
		return false
	}
	m, err := h.coordinator.GetClientMember(deviceID, networkID)
	if err != nil || m == nil {
		return false
	}
	return m.Status != MemberStatusRemoved && m.Status != MemberStatusLeaved
}

func normalizeNonEmptyStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

// firstNonEmptyTrimmed removed (S5-B2): only used by non-LAN gather path.

// Write
func writeRawMessage(conn net.Conn, data []byte) error {
	// 长度前缀必须用大端（网络字节序），与 server/protocol.go(binary.BigEndian)
	// 及客户端 framing(u32::from_be_bytes) 保持一致。
	// 历史实现误用小端，导致较大帧的长度被对端按大端解析成超大值
	// （read_frame 报 "Message too large"），并造成帧错位。
	// 单次 Write 整帧（length+body），避免与其它 goroutine 的写交错损坏帧边界。
	length := uint32(len(data))
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], length)
	copy(buf[4:], data)

	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("write message: %w", err)
	}

	return nil
}

// verifyNetworkOwner returns nil when userID matches the network's OwnerUserID.
// Networks created before the owner field was introduced have an empty OwnerUserID;
// for those legacy networks the check is skipped so that any authenticated user
// can still manage them (delete, update CIDR, remove members, etc.).
func (h *WireGuardHandler) verifyNetworkOwner(networkID, userID string) error {
	network, err := h.coordinator.GetNetwork(networkID)
	if err != nil || network == nil {
		return fmt.Errorf("network not found: %s", networkID)
	}
	ownerID := strings.TrimSpace(network.OwnerUserID)
	if ownerID == "" {
		// Legacy network without an owner — skip ownership verification.
		return nil
	}
	if ownerID != userID {
		return fmt.Errorf("permission denied: only the network owner can perform this operation")
	}
	return nil
}

// Handle
func (h *WireGuardHandler) HandleCreateNetwork(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGCreateNetworkRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGCreateNetworkRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	header := msg.Header(nil)

	logger.Infof("handle create network: network_id=%s, name=%s, cidr=%s",
		string(req.NetworkId()), string(req.Name()), string(req.Cidr()))

	var relayMode RelayMode
	switch req.RelayMode() {
	case fbMsg.WGRelayModeDISABLED:
		relayMode = RelayModeDisabled
	case fbMsg.WGRelayModeOPTIONAL:
		relayMode = RelayModeOptional
	case fbMsg.WGRelayModeFORCE:
		relayMode = RelayModeForce
	default:
		relayMode = RelayModeOptional
	}

	// Create — owner identity MUST come from the authenticated session,
	// not from the request body (which the client can forge).
	edgeID := h.edgeID
	network, relayInfo, err := h.coordinator.CreateNetworkWithRelay(&CreateNetworkRequest{
		ID:                string(req.NetworkId()),
		Name:              string(req.Name()),
		CIDR:              string(req.Cidr()),
		CoordinatorEdgeID: edgeID,
		OwnerUserID:       ctx.UserID,
		RelayMode:         relayMode,
	})

	builder := flatbuffers.NewBuilder(1024)

	var networkIDOffset, errorMsgOffset, relayNodeOffset flatbuffers.UOffsetT
	var suggestedCidrsOffset flatbuffers.UOffsetT
	errorCode := uint32(1)
	if err != nil {
		logger.Errorf("create network failed: %v", err)
		errorMsgOffset = builder.CreateString(err.Error())
		if conflict := AsCIDRConflict(err); conflict != nil {
			errorCode = 2 // CIDR_CONFLICT
			if len(conflict.SuggestedCIDRs) > 0 {
				cidrOffsets := make([]flatbuffers.UOffsetT, len(conflict.SuggestedCIDRs))
				for i, c := range conflict.SuggestedCIDRs {
					cidrOffsets[i] = builder.CreateString(c)
				}
				fbMsg.WGCreateNetworkResponseStartSuggestedCidrsVector(builder, len(cidrOffsets))
				for i := len(cidrOffsets) - 1; i >= 0; i-- {
					builder.PrependUOffsetT(cidrOffsets[i])
				}
				suggestedCidrsOffset = builder.EndVector(len(cidrOffsets))
			}
		}
	} else {
		networkIDOffset = builder.CreateString(network.ID)
		if relayInfo != nil {
			relayMemberIDOff := builder.CreateString(relayInfo.MemberID)
			relayPubKeyOff := builder.CreateString(relayInfo.PublicKey)
			relayEndpointOff := builder.CreateString(relayInfo.Endpoint)
			relayIPOff := builder.CreateString(relayInfo.AssignedIP)
			peerEndpointOffsets := make([]flatbuffers.UOffsetT, 0, len(relayInfo.PeerEndpoints))
			for _, peer := range relayInfo.PeerEndpoints {
				publicKeyOff := builder.CreateString(peer.PublicKey)
				assignedIPOff := builder.CreateString(peer.AssignedIP)
				endpointOff := builder.CreateString(peer.Endpoint)
				fbMsg.WGRelayPeerEndpointInfoStart(builder)
				fbMsg.WGRelayPeerEndpointInfoAddPublicKey(builder, publicKeyOff)
				fbMsg.WGRelayPeerEndpointInfoAddAssignedIp(builder, assignedIPOff)
				fbMsg.WGRelayPeerEndpointInfoAddEndpoint(builder, endpointOff)
				fbMsg.WGRelayPeerEndpointInfoAddListenPort(builder, uint32(peer.ListenPort))
				peerEndpointOffsets = append(peerEndpointOffsets, fbMsg.WGRelayPeerEndpointInfoEnd(builder))
			}
			fbMsg.WGRelayNodeInfoStartPeerEndpointsVector(builder, len(peerEndpointOffsets))
			for i := len(peerEndpointOffsets) - 1; i >= 0; i-- {
				builder.PrependUOffsetT(peerEndpointOffsets[i])
			}
			peerEndpointsOff := builder.EndVector(len(peerEndpointOffsets))
			fbMsg.WGRelayNodeInfoStart(builder)
			fbMsg.WGRelayNodeInfoAddMemberId(builder, relayMemberIDOff)
			fbMsg.WGRelayNodeInfoAddPublicKey(builder, relayPubKeyOff)
			fbMsg.WGRelayNodeInfoAddEndpoint(builder, relayEndpointOff)
			fbMsg.WGRelayNodeInfoAddAssignedIp(builder, relayIPOff)
			fbMsg.WGRelayNodeInfoAddListenPort(builder, uint32(relayInfo.ListenPort))
			fbMsg.WGRelayNodeInfoAddPeerEndpoints(builder, peerEndpointsOff)
			relayNodeOffset = fbMsg.WGRelayNodeInfoEnd(builder)
		}
	}

	fbMsg.WGCreateNetworkResponseStart(builder)
	fbMsg.WGCreateNetworkResponseAddSuccess(builder, err == nil)
	if err == nil {
		fbMsg.WGCreateNetworkResponseAddNetworkId(builder, networkIDOffset)
		fbMsg.WGCreateNetworkResponseAddStatus(builder, fbMsg.WGNetworkStatusACTIVE)
		if relayInfo != nil {
			fbMsg.WGCreateNetworkResponseAddRelayNode(builder, relayNodeOffset)
		}
	} else {
		fbMsg.WGCreateNetworkResponseAddErrorCode(builder, errorCode)
		fbMsg.WGCreateNetworkResponseAddErrorMessage(builder, errorMsgOffset)
		if suggestedCidrsOffset != 0 {
			fbMsg.WGCreateNetworkResponseAddSuggestedCidrs(builder, suggestedCidrsOffset)
		}
	}
	respBodyOffset := fbMsg.WGCreateNetworkResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_CREATE_NETWORK_ACK)
	fbMsg.MessageHeaderAddSeq(builder, header.Seq())
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGCreateNetworkResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)

	// Send
	data := builder.FinishedBytes()
	return writeRawMessage(ctx.Conn, data)
}

// Handle
func (h *WireGuardHandler) HandleJoinNetwork(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGJoinNetworkRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGJoinNetworkRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	header := msg.Header(nil)

	networkID := string(req.NetworkId())
	// Use bare deviceID as the canonical clientID for self-join.
	// When the request carries an explicit ClientId (proxy-add / addDevice),
	// use that instead so Edge creates a member for the remote device.
	// member.go supports "代加成员先以 clientId 占位公钥加入".
	rawClientID := string(req.ClientId())
	clientID := ctx.DeviceID
	if rawClientID != "" && rawClientID != ctx.DeviceID {
		clientID = rawClientID
	}
	publicKey := string(req.PublicKey())
	hostname := string(req.Hostname())
	inviteToken := string(req.InviteToken())
	logger.Infof("handle join network: network_id=%s, client_id=%s, raw_client_id=%s, hostname=%s", networkID, clientID, rawClientID, hostname)

	// Authorization: non-owner must provide a valid invite token.
	network, netErr := h.coordinator.GetNetwork(networkID)
	if netErr != nil || network == nil {
		// Network not found — return a generic error to avoid leaking existence.
		builder := flatbuffers.NewBuilder(256)
		errMsgOff := builder.CreateString("network not found")
		fbMsg.WGJoinNetworkResponseStart(builder)
		fbMsg.WGJoinNetworkResponseAddSuccess(builder, false)
		fbMsg.WGJoinNetworkResponseAddErrorCode(builder, 1)
		fbMsg.WGJoinNetworkResponseAddErrorMessage(builder, errMsgOff)
		respOff := fbMsg.WGJoinNetworkResponseEnd(builder)
		fbMsg.MessageHeaderStart(builder)
		fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_JOIN_NETWORK_ACK)
		fbMsg.MessageHeaderAddSeq(builder, header.Seq())
		fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
		hdrOff := fbMsg.MessageHeaderEnd(builder)
		fbMsg.MessageStart(builder)
		fbMsg.MessageAddHeader(builder, hdrOff)
		fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGJoinNetworkResponse)
		fbMsg.MessageAddBody(builder, respOff)
		msgOff := fbMsg.MessageEnd(builder)
		builder.Finish(msgOff)
		return writeRawMessage(ctx.Conn, builder.FinishedBytes())
	}
	// Non-owner join normally requires a valid invite token. Skip the token
	// check when the device already proves durable authorization for THIS
	// network: its mTLS certificate carries an explicit "network:<id>"/"*"
	// scope (granted at bootstrap only after the token was validated), or it is
	// already an active (non-removed, non-leaved) member. This lets a restart
	// re-join with the existing certificate instead of re-presenting the
	// single-use, usually-expired invite token. An unscoped certificate on a
	// first join still requires the token.
	if network.OwnerUserID != "" && network.OwnerUserID != ctx.UserID &&
		!hasExplicitNetworkScope(ctx, networkID) && !h.isActiveMember(ctx.DeviceID, networkID) {
		if inviteToken == "" {
			builder := flatbuffers.NewBuilder(256)
			errMsgOff := builder.CreateString("invite token required for non-owner join")
			fbMsg.WGJoinNetworkResponseStart(builder)
			fbMsg.WGJoinNetworkResponseAddSuccess(builder, false)
			fbMsg.WGJoinNetworkResponseAddErrorCode(builder, 2)
			fbMsg.WGJoinNetworkResponseAddErrorMessage(builder, errMsgOff)
			respOff := fbMsg.WGJoinNetworkResponseEnd(builder)
			fbMsg.MessageHeaderStart(builder)
			fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_JOIN_NETWORK_ACK)
			fbMsg.MessageHeaderAddSeq(builder, header.Seq())
			fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
			hdrOff := fbMsg.MessageHeaderEnd(builder)
			fbMsg.MessageStart(builder)
			fbMsg.MessageAddHeader(builder, hdrOff)
			fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGJoinNetworkResponse)
			fbMsg.MessageAddBody(builder, respOff)
			msgOff := fbMsg.MessageEnd(builder)
			builder.Finish(msgOff)
			return writeRawMessage(ctx.Conn, builder.FinishedBytes())
		}
		if _, tokErr := h.inviteStore.Validate(inviteToken, networkID); tokErr != nil {
			builder := flatbuffers.NewBuilder(256)
			errMsgOff := builder.CreateString(tokErr.Error())
			fbMsg.WGJoinNetworkResponseStart(builder)
			fbMsg.WGJoinNetworkResponseAddSuccess(builder, false)
			fbMsg.WGJoinNetworkResponseAddErrorCode(builder, 3)
			fbMsg.WGJoinNetworkResponseAddErrorMessage(builder, errMsgOff)
			respOff := fbMsg.WGJoinNetworkResponseEnd(builder)
			fbMsg.MessageHeaderStart(builder)
			fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_JOIN_NETWORK_ACK)
			fbMsg.MessageHeaderAddSeq(builder, header.Seq())
			fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
			hdrOff := fbMsg.MessageHeaderEnd(builder)
			fbMsg.MessageStart(builder)
			fbMsg.MessageAddHeader(builder, hdrOff)
			fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGJoinNetworkResponse)
			fbMsg.MessageAddBody(builder, respOff)
			msgOff := fbMsg.MessageEnd(builder)
			builder.Finish(msgOff)
			return writeRawMessage(ctx.Conn, builder.FinishedBytes())
		}
		logger.Infof("join network: invite token validated for non-owner user=%s network=%s", ctx.UserID, networkID)
	}

	memberID := fmt.Sprintf("member-%s-%s", clientID, networkID[:8])

	joinStart := time.Now()
	member, err := h.coordinator.JoinNetwork(&JoinNetworkRequest{
		MemberID:  memberID,
		NetworkID: networkID,
		HostName:  hostname,
		ClientID:  clientID,
		UserID:    ctx.UserID,
		PublicKey: publicKey,
	})
	logger.Infof("[JoinPerf] network_id=%s coordinator.JoinNetwork elapsed=%v", networkID, time.Since(joinStart))

	builder := flatbuffers.NewBuilder(1024)

	var memberIDOffset, assignedIPOffset, errorMsgOffset flatbuffers.UOffsetT
	if err != nil {
		logger.Errorf("join network failed: %v", err)
		errorMsgOffset = builder.CreateString(err.Error())
	} else {
		memberIDOffset = builder.CreateString(member.ID)
		assignedIPOffset = builder.CreateString(member.IP)
	}

	fbMsg.WGJoinNetworkResponseStart(builder)
	fbMsg.WGJoinNetworkResponseAddSuccess(builder, err == nil)
	if err == nil {
		fbMsg.WGJoinNetworkResponseAddMemberId(builder, memberIDOffset)
		fbMsg.WGJoinNetworkResponseAddAssignedIp(builder, assignedIPOffset)
		fbMsg.WGJoinNetworkResponseAddStatus(builder, fbMsg.WGMemberStatusACTIVE)
	} else {
		fbMsg.WGJoinNetworkResponseAddErrorCode(builder, 1)
		fbMsg.WGJoinNetworkResponseAddErrorMessage(builder, errorMsgOffset)
	}
	respBodyOffset := fbMsg.WGJoinNetworkResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_JOIN_NETWORK_ACK)
	fbMsg.MessageHeaderAddSeq(builder, header.Seq())
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGJoinNetworkResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)

	// Send
	data := builder.FinishedBytes()
	if err := writeRawMessage(ctx.Conn, data); err != nil {
		return err
	}

	// Post-response side effects (SetMemberOnline, PushNetworkEvent)
	// are detached from the handler goroutine.
	// PushNetworkEvent writes to every online member's TCP connection;
	// a slow peer can block conn.Write indefinitely, stalling the
	// handleSession read loop and starving all subsequent requests
	// from the same client.
	if member != nil {
		networkID := string(req.NetworkId())
		pk := publicKey
		cid := clientID
		mID := member.ID
		go func() {
			if pk != "" && pk != cid {
				if err := h.coordinator.SetMemberOnline(mID); err != nil {
					logger.Warnf("set member online failed: %v", err)
				}
			}
			if err := h.PushNetworkEvent(networkID, fbMsg.WGNetworkEventActionUPSERT); err != nil {
				logger.Warnf("push network event after join failed: %v", err)
			}
		}()
	}

	return nil
}

// HandleCreateInvite generates an invite token for a WireGuard network.
// Only the network owner can create invites.
func (h *WireGuardHandler) HandleCreateInvite(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGCreateInviteRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGCreateInviteRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	header := msg.Header(nil)

	networkID := string(req.NetworkId())
	expiresInSecs := req.ExpiresInSecs()
	maxUses := req.MaxUses()

	logger.Infof("handle create invite: network_id=%s, expires_in_secs=%d, max_uses=%d", networkID, expiresInSecs, maxUses)

	// Authorization: only the network owner can create invites.
	network, err := h.coordinator.GetNetwork(networkID)
	if err != nil || network == nil {
		err = fmt.Errorf("network not found: %s", networkID)
	} else if network.OwnerUserID == "" || network.OwnerUserID != ctx.UserID {
		err = fmt.Errorf("only the network owner can create invites")
	}

	builder := flatbuffers.NewBuilder(512)
	var tokenOffset, errorMsgOffset flatbuffers.UOffsetT
	var expiresAt uint64
	success := false
	errorCode := uint32(0)

	if err != nil {
		errorCode = 1
		errorMsgOffset = builder.CreateString(err.Error())
	} else {
		tok, createErr := h.inviteStore.Create(networkID, network.OwnerUserID, expiresInSecs, maxUses)
		if createErr != nil {
			errorCode = 1
			errorMsgOffset = builder.CreateString(createErr.Error())
		} else {
			success = true
			tokenOffset = builder.CreateString(tok.Token)
			expiresAt = uint64(tok.ExpiresAt.UnixNano() / 1e6)
		}
	}

	fbMsg.WGCreateInviteResponseStart(builder)
	fbMsg.WGCreateInviteResponseAddSuccess(builder, success)
	if success {
		fbMsg.WGCreateInviteResponseAddInviteToken(builder, tokenOffset)
		fbMsg.WGCreateInviteResponseAddExpiresAt(builder, expiresAt)
	} else {
		fbMsg.WGCreateInviteResponseAddErrorCode(builder, errorCode)
		fbMsg.WGCreateInviteResponseAddErrorMessage(builder, errorMsgOffset)
	}
	respBodyOffset := fbMsg.WGCreateInviteResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_CREATE_INVITE_ACK)
	fbMsg.MessageHeaderAddSeq(builder, header.Seq())
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGCreateInviteResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	return writeRawMessage(ctx.Conn, builder.FinishedBytes())
}

// HandleLeaveNetwork marks a caller temporarily disconnected or leaves/removes
// a WG member. When member_id is empty, the caller targets itself (resolved via
// device ID). A temporary request may only target the caller; permanent removal
// of another member requires network ownership. Relay members cannot be removed.
func (h *WireGuardHandler) HandleLeaveNetwork(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGLeaveNetworkRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGLeaveNetworkRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	header := msg.Header(nil)

	networkID := string(req.NetworkId())
	requestedMemberID := strings.TrimSpace(string(req.MemberId()))
	temporary := req.Temporary()

	// Resolve self member ID for the caller.
	var selfMemberID string
	if ctx.DeviceID != "" {
		if m, err := h.coordinator.GetClientMember(ctx.DeviceID, networkID); err == nil && m != nil {
			selfMemberID = m.ID
		}
	}

	// Determine the effective target member ID.
	memberID := requestedMemberID
	if memberID == "" {
		memberID = selfMemberID
	}

	logger.Infof("handle leave network: network_id=%s, member_id=%s, self_member_id=%s", networkID, memberID, selfMemberID)

	// Authorization: removing another member requires network ownership.
	isSelf := memberID != "" && memberID == selfMemberID
	var err error
	if temporary && !isSelf {
		err = fmt.Errorf("temporary leave is only allowed for the caller's own membership")
	}
	if !isSelf && memberID != "" {
		if err == nil {
			network, netErr := h.coordinator.GetNetwork(networkID)
			if netErr != nil || network == nil {
				err = fmt.Errorf("network not found: %s", networkID)
			} else if ownerID := strings.TrimSpace(network.OwnerUserID); ownerID != "" && ownerID != ctx.UserID {
				err = fmt.Errorf("only the network owner can remove other members")
			}
		}
	}

	// Prevent removing relay members via this API.
	if err == nil && memberID != "" {
		if overview, ovErr := h.getNetworkOverview(networkID); ovErr == nil && overview != nil {
			for _, m := range overview.Members {
				if m != nil && m.ID == memberID && m.IsRelay {
					err = fmt.Errorf("cannot remove relay member")
					break
				}
			}
		}
	}

	// Capture public key before removal for relay notification.
	var leavingPublicKey string
	if err == nil && memberID != "" {
		// Look up the target member's public key from the overview.
		if overview, ovErr := h.getNetworkOverview(networkID); ovErr == nil && overview != nil {
			for _, m := range overview.Members {
				if m != nil && m.ID == memberID {
					leavingPublicKey = m.PublicKey
					break
				}
			}
		}
	}

	if err == nil {
		if memberID == "" {
			err = fmt.Errorf("member not found for network %s", networkID)
		} else if isSelf && temporary {
			// A process/transport shutdown is a transient disconnect. Keep the
			// membership and path-coordination eligibility for the next session.
			err = h.coordinator.SetMemberDisconnected(memberID)
		} else if isSelf {
			// Explicit self-leave is a permanent membership departure (soft
			// deletion in the member list) and revokes path coordination.
			err = h.coordinator.SetMemberOffline(memberID)
			if err == nil && leavingPublicKey != "" {
				h.coordinator.NotifyRelayPeerLeft(networkID, leavingPublicKey)
			}
		} else {
			// Owner removing another member: hard delete. The member is
			// fully removed (IP released, indexes cleaned, storage deleted).
			// They can be added back via the "add device" flow.
			err = h.coordinator.RemoveMember(memberID)
			if err == nil && leavingPublicKey != "" {
				h.coordinator.NotifyRelayPeerLeft(networkID, leavingPublicKey)
			}
		}
	}

	builder := flatbuffers.NewBuilder(512)
	var errorMsgOffset flatbuffers.UOffsetT
	if err != nil {
		logger.Errorf("leave network failed: %v", err)
		errorMsgOffset = builder.CreateString(err.Error())
	}

	fbMsg.WGLeaveNetworkResponseStart(builder)
	fbMsg.WGLeaveNetworkResponseAddSuccess(builder, err == nil)
	if err != nil {
		fbMsg.WGLeaveNetworkResponseAddErrorCode(builder, 1)
		fbMsg.WGLeaveNetworkResponseAddErrorMessage(builder, errorMsgOffset)
	}
	respBodyOffset := fbMsg.WGLeaveNetworkResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_LEAVE_NETWORK_ACK)
	fbMsg.MessageHeaderAddSeq(builder, header.Seq())
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGLeaveNetworkResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	if writeErr := writeRawMessage(ctx.Conn, builder.FinishedBytes()); writeErr != nil {
		return writeErr
	}

	// Detach post-response broadcast from the handler goroutine.
	// PushNetworkEvent writes to every online member's TCP connection;
	// a slow peer can block conn.Write and stall the read loop.
	if err == nil {
		go func() {
			if pushErr := h.PushNetworkEvent(networkID, fbMsg.WGNetworkEventActionUPSERT); pushErr != nil {
				logger.Warnf("push network event after leave failed: %v", pushErr)
			}
		}()
	}
	return nil
}

// Handle
func (h *WireGuardHandler) HandleListNetworks(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGListNetworksRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGListNetworksRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	header := msg.Header(nil)

	includeDeleted := req.IncludeDeleted()
	networks := h.coordinator.ListNetworks()

	builder := flatbuffers.NewBuilder(4096)
	networkOffsets := make([]flatbuffers.UOffsetT, 0, len(networks))
	for _, network := range networks {
		if network == nil {
			continue
		}
		if !includeDeleted && network.Status == NetworkStatusDeleted {
			continue
		}
		// Certificate scope check: scoped certs can only see networks in their scope.
		if !hasNetworkAccess(ctx, network.ID) {
			continue
		}
		// Permission filter: only return networks the caller owns or has joined.
		if !h.isNetworkOwnerOrMember(ctx, network) {
			continue
		}
		overview, err := h.getNetworkOverview(network.ID)
		if err != nil || overview == nil {
			logger.Warnf("skip wireguard network summary build: network_id=%s err=%v", network.ID, err)
			continue
		}
		networkOffsets = append(
			networkOffsets,
			buildWGNetworkSummaryOffset(builder, overview.Network, overview.Members, overview.RelayNode, ctx.DeviceID),
		)
	}

	fbMsg.WGListNetworksResponseStartNetworksVector(builder, len(networkOffsets))
	for i := len(networkOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(networkOffsets[i])
	}
	networksVectorOffset := builder.EndVector(len(networkOffsets))

	fbMsg.WGListNetworksResponseStart(builder)
	fbMsg.WGListNetworksResponseAddSuccess(builder, true)
	fbMsg.WGListNetworksResponseAddRevision(builder, uint64(getNowMillis()))
	fbMsg.WGListNetworksResponseAddNetworks(builder, networksVectorOffset)
	respBodyOffset := fbMsg.WGListNetworksResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_LIST_NETWORKS_ACK)
	fbMsg.MessageHeaderAddSeq(builder, header.Seq())
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGListNetworksResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	return writeRawMessage(ctx.Conn, builder.FinishedBytes())
}

// Handle
func (h *WireGuardHandler) HandleGetNetwork(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGGetNetworkRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGGetNetworkRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	header := msg.Header(nil)

	networkID := string(req.NetworkId())

	// Certificate scope check: scoped certs can only access networks in their scope.
	if !hasNetworkAccess(ctx, networkID) {
		networkID = "" // Force not-found below
	}

	overview, err := h.getVersionedNetworkOverview(networkID)

	// Permission check: caller must be owner or member.
	if err == nil && overview != nil {
		if !h.isNetworkOwnerOrMember(ctx, overview.Network) {
			err = fmt.Errorf("network not found: %s", networkID)
			overview = nil
		}
	}

	// Filter LAN endpoints to same-NAT peers only for the requesting client.
	if err == nil && overview != nil {
		overview.LANPeerEndpoints = h.filterLANEndpointsForRequester(overview, networkID, ctx.DeviceID)
	}

	builder := flatbuffers.NewBuilder(4096)
	var snapshotOffset, errorMsgOffset flatbuffers.UOffsetT
	if err != nil || overview == nil {
		if err == nil {
			err = fmt.Errorf("network not found: %s", networkID)
		}
		logger.Errorf("get network failed: %v", err)
		errorMsgOffset = builder.CreateString(err.Error())
	} else {
		overview = h.withPathBootstrap(ctx, overview)
		snapshotOffset = buildWGNetworkRuntimeSnapshotOffset(builder, overview, ctx.UserID, ctx.DeviceID)
	}

	fbMsg.WGGetNetworkResponseStart(builder)
	fbMsg.WGGetNetworkResponseAddSuccess(builder, err == nil)
	if err == nil {
		fbMsg.WGGetNetworkResponseAddSnapshot(builder, snapshotOffset)
	} else {
		fbMsg.WGGetNetworkResponseAddErrorCode(builder, 1)
		fbMsg.WGGetNetworkResponseAddErrorMessage(builder, errorMsgOffset)
	}
	respBodyOffset := fbMsg.WGGetNetworkResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_GET_NETWORK_ACK)
	fbMsg.MessageHeaderAddSeq(builder, header.Seq())
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGGetNetworkResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	return writeRawMessage(ctx.Conn, builder.FinishedBytes())
}

// Handle
func (h *WireGuardHandler) HandleDeleteNetwork(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGDeleteNetworkRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGDeleteNetworkRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	header := msg.Header(nil)

	networkID := string(req.NetworkId())

	// Authorization: only the network owner can delete the network.
	var err error
	if authErr := h.verifyNetworkOwner(networkID, ctx.UserID); authErr != nil {
		logger.Warnf("delete network denied: network=%s user=%s err=%v", networkID, ctx.UserID, authErr)
		err = authErr
	}

	// 删除前捕获成员 clientID，删除后网络已不存在，无法再从 overview 取成员。
	var memberClientIDs []string
	if err == nil {
		if overview, ovErr := h.getNetworkOverview(networkID); ovErr == nil && overview != nil {
			for _, member := range overview.Members {
				if cid := strings.TrimSpace(member.ClientID); cid != "" {
					memberClientIDs = append(memberClientIDs, cid)
				}
			}
		}
	}

	if err == nil {
		err = h.coordinator.DeleteNetwork(networkID)
	}

	builder := flatbuffers.NewBuilder(1024)
	var networkIDOffset, errorMsgOffset flatbuffers.UOffsetT
	if err != nil {
		logger.Errorf("delete network failed: %v", err)
		errorMsgOffset = builder.CreateString(err.Error())
	} else {
		networkIDOffset = builder.CreateString(networkID)
	}

	fbMsg.WGDeleteNetworkResponseStart(builder)
	fbMsg.WGDeleteNetworkResponseAddSuccess(builder, err == nil)
	if err == nil {
		fbMsg.WGDeleteNetworkResponseAddNetworkId(builder, networkIDOffset)
	} else {
		fbMsg.WGDeleteNetworkResponseAddErrorCode(builder, 1)
		fbMsg.WGDeleteNetworkResponseAddErrorMessage(builder, errorMsgOffset)
	}
	respBodyOffset := fbMsg.WGDeleteNetworkResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_DELETE_NETWORK_ACK)
	fbMsg.MessageHeaderAddSeq(builder, header.Seq())
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGDeleteNetworkResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	if writeErr := writeRawMessage(ctx.Conn, builder.FinishedBytes()); writeErr != nil {
		return writeErr
	}

	// 删除成功后向原成员广播 DELETE 事件（不含 snapshot）。
	if err == nil && len(memberClientIDs) > 0 {
		h.pushNetworkDeleteEvent(networkID, memberClientIDs)
	}
	return nil
}

// pushNetworkDeleteEvent 向给定成员广播 network DELETE 事件。
// 用于网络已删除、无法再从 coordinator 取 overview 的场景。
func (h *WireGuardHandler) pushNetworkDeleteEvent(networkID string, clientIDs []string) {
	state, epoch := h.runtimeVersions.network(networkID)
	state.mu.Lock()
	defer state.mu.Unlock()
	revision, err := h.runtimeVersions.advanceLocked(state)
	if err != nil {
		logger.Errorf("WG network delete event version failed: network=%s err=%v", networkID, err)
		return
	}

	builder := flatbuffers.NewBuilder(256)
	networkIDOffset := builder.CreateString(networkID)
	epochOffset := builder.CreateString(epoch)

	fbMsg.WGNetworkEventPushStart(builder)
	fbMsg.WGNetworkEventPushAddAction(builder, fbMsg.WGNetworkEventActionDELETE)
	fbMsg.WGNetworkEventPushAddNetworkId(builder, networkIDOffset)
	fbMsg.WGNetworkEventPushAddNextRevision(builder, revision)
	fbMsg.WGNetworkEventPushAddRevisionEpoch(builder, epochOffset)
	pushOffset := fbMsg.WGNetworkEventPushEnd(builder)

	sessionStrOffset := builder.CreateString("")
	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_NETWORK_EVENT_PUSH)
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	fbMsg.MessageHeaderAddSessionId(builder, sessionStrOffset)
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGNetworkEventPush)
	fbMsg.MessageAddBody(builder, pushOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	data := builder.FinishedBytes()

	for _, clientID := range clientIDs {
		if err := h.sessions.PushToClient(clientID, data); err != nil {
			logger.Warnf("push network delete event to client %s (network %s) failed: %v", clientID, networkID, err)
		}
	}
	logger.Infof("pushed network delete event: network=%s members=%d", networkID, len(clientIDs))
}

// Handle
func (h *WireGuardHandler) HandleNetworkRuntimeRequest(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGNetworkRuntimeRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGNetworkRuntimeRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	return h.sendNetworkRuntimeResponse(ctx, string(req.NetworkId()), msg.Header(nil).Seq())
}

// A path proposal also receives this authenticated snapshot as its acceptance
// receipt. It is distinct from bilateral application completion.
func (h *WireGuardHandler) sendNetworkRuntimeResponse(ctx HandlerSession, networkID string, seq uint32) error {

	// Certificate scope check.
	if !hasNetworkAccess(ctx, networkID) {
		networkID = "" // Force not-found below
	}

	overview, err := h.getVersionedNetworkOverview(networkID)

	// Presence is projected from current control sessions. A runtime read does
	// not update relay handshake observations or assert native WG readiness.
	if err == nil && overview != nil && !h.isNetworkOwnerOrMember(ctx, overview.Network) {
		err = fmt.Errorf("network not found: %s", networkID)
		overview = nil
	}
	if err == nil && overview != nil {
		// Filter LAN endpoints to same-NAT peers only for the requesting client.
		overview.LANPeerEndpoints = h.filterLANEndpointsForRequester(overview, networkID, ctx.DeviceID)
	}

	if err == nil && overview != nil {
		var bootstrapErr error
		overview, bootstrapErr = h.withPathBootstrapResult(ctx, overview)
		// Ordinary readers still receive the network model. A client declaring
		// coordination needs a real bootstrap or an explicit failure reason.
		if overview.Network != nil && overview.Network.RelayMode == RelayModeOptional {
			for _, capability := range ctx.Capabilities {
				if capability == pathcoord.Capability {
					err = bootstrapErr
					break
				}
			}
		}
	}

	builder := flatbuffers.NewBuilder(4096)
	var snapshotOffset, errorMsgOffset flatbuffers.UOffsetT
	if err != nil || overview == nil {
		if err == nil {
			err = fmt.Errorf("network not found: %s", networkID)
		}
		logger.Warnf("network runtime request failed: network=%s device=%s session=%s: %v", networkID, ctx.DeviceID, ctx.SessionID, err)
		errorMsgOffset = builder.CreateString(err.Error())
	} else {
		snapshotOffset = buildWGNetworkRuntimeSnapshotOffset(builder, overview, ctx.UserID, ctx.DeviceID)
	}

	fbMsg.WGNetworkRuntimeResponseStart(builder)
	fbMsg.WGNetworkRuntimeResponseAddSuccess(builder, err == nil)
	if err == nil {
		fbMsg.WGNetworkRuntimeResponseAddSnapshot(builder, snapshotOffset)
	} else {
		fbMsg.WGNetworkRuntimeResponseAddErrorCode(builder, 1)
		fbMsg.WGNetworkRuntimeResponseAddErrorMessage(builder, errorMsgOffset)
	}
	respBodyOffset := fbMsg.WGNetworkRuntimeResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_NETWORK_RUNTIME_RESPONSE)
	fbMsg.MessageHeaderAddSeq(builder, seq)
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGNetworkRuntimeResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	return writeRawMessage(ctx.Conn, builder.FinishedBytes())
}

// HandleListAvailableDevices 列出当前用户在线、且尚未加入目标网络的设备，供「扫描在线设备」使用。
func (h *WireGuardHandler) HandleListAvailableDevices(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGListAvailableDevicesRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGListAvailableDevicesRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	header := msg.Header(nil)

	networkID := strings.TrimSpace(string(req.NetworkId()))

	// Certificate scope check: scoped certs can only query devices for networks in their scope.
	if networkID != "" && !hasNetworkAccess(ctx, networkID) {
		networkID = "" // Clear to skip member collection, but still return user's devices
	}

	// 收集该网络已有成员的 clientID，用于过滤。
	memberClientIDs := make(map[string]struct{})
	if networkID != "" {
		if overview, err := h.getNetworkOverview(networkID); err == nil && overview != nil {
			for _, member := range overview.Members {
				if member == nil || member.Status == MemberStatusRemoved {
					continue
				}
				if cid := strings.TrimSpace(member.ClientID); cid != "" {
					memberClientIDs[cid] = struct{}{}
				}
			}
		}
	}

	var devices []OnlineDeviceInfo
	if h.deviceLister != nil {
		devices = h.deviceLister.ListOnlineDevicesByUser(ctx.UserID)
	}

	builder := flatbuffers.NewBuilder(1024)
	networkIDOffset := builder.CreateString(networkID)

	deviceOffsets := make([]flatbuffers.UOffsetT, 0, len(devices))
	for _, device := range devices {
		clientID := strings.TrimSpace(device.ClientID)
		if clientID == "" {
			continue
		}
		if _, isMember := memberClientIDs[clientID]; isMember {
			continue // 已是成员，跳过
		}
		clientIDOffset := builder.CreateString(clientID)
		deviceIDOffset := builder.CreateString(device.DeviceID)
		hostnameOffset := builder.CreateString(device.Hostname)

		fbMsg.WGAvailableDeviceInfoStart(builder)
		fbMsg.WGAvailableDeviceInfoAddClientId(builder, clientIDOffset)
		fbMsg.WGAvailableDeviceInfoAddDeviceId(builder, deviceIDOffset)
		fbMsg.WGAvailableDeviceInfoAddHostname(builder, hostnameOffset)
		fbMsg.WGAvailableDeviceInfoAddLastActive(builder, uint64(device.LastActive))
		deviceOffsets = append(deviceOffsets, fbMsg.WGAvailableDeviceInfoEnd(builder))
	}

	fbMsg.WGListAvailableDevicesResponseStartDevicesVector(builder, len(deviceOffsets))
	for i := len(deviceOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(deviceOffsets[i])
	}
	devicesVectorOffset := builder.EndVector(len(deviceOffsets))

	fbMsg.WGListAvailableDevicesResponseStart(builder)
	fbMsg.WGListAvailableDevicesResponseAddSuccess(builder, true)
	fbMsg.WGListAvailableDevicesResponseAddNetworkId(builder, networkIDOffset)
	fbMsg.WGListAvailableDevicesResponseAddDevices(builder, devicesVectorOffset)
	respBodyOffset := fbMsg.WGListAvailableDevicesResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_LIST_AVAILABLE_DEVICES_ACK)
	fbMsg.MessageHeaderAddSeq(builder, header.Seq())
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGListAvailableDevicesResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	return writeRawMessage(ctx.Conn, builder.FinishedBytes())
}

// Handle
func (h *WireGuardHandler) HandleListMembers(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGListMembersRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGListMembersRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	header := msg.Header(nil)

	networkID := string(req.NetworkId())
	onlineOnly := req.OnlineOnly()

	logger.Infof("handle list members: network_id=%s, online_only=%v", networkID, onlineOnly)

	// Certificate scope check.
	if !hasNetworkAccess(ctx, networkID) {
		networkID = "" // Force not-found below
	}

	overview, err := h.getNetworkOverview(networkID)
	if err == nil && overview == nil {
		err = fmt.Errorf("network not found: %s", networkID)
	}

	builder := flatbuffers.NewBuilder(2048)
	var errorMsgOffset flatbuffers.UOffsetT
	memberOffsets := make([]flatbuffers.UOffsetT, 0)
	if err != nil {
		logger.Errorf("list members failed: %v", err)
		errorMsgOffset = builder.CreateString(err.Error())
	} else {
		members := selectListedMembers(overview.Members, onlineOnly)
		memberOffsets = make([]flatbuffers.UOffsetT, 0, len(members))
		for _, m := range members {
			memberIDOffset := builder.CreateString(m.ID)
			// Wire format sends bare deviceID; strip userID- prefix.
			wireDeviceID := m.ClientID
			if idx := strings.Index(m.ClientID, "-"); idx >= 0 {
				wireDeviceID = m.ClientID[idx+1:]
			}
			clientIDOffset := builder.CreateString(wireDeviceID)
			ipOffset := builder.CreateString(m.IP)

			fbMsg.WGMemberInfoStart(builder)
			fbMsg.WGMemberInfoAddMemberId(builder, memberIDOffset)
			fbMsg.WGMemberInfoAddClientId(builder, clientIDOffset)
			fbMsg.WGMemberInfoAddAssignedIp(builder, ipOffset)
			fbMsg.WGMemberInfoAddStatus(builder, mapMemberStatusToFB(m))
			fbMsg.WGMemberInfoAddLastOnline(builder, uint64(m.LastOnline.Unix()))
			memberOffsets = append(memberOffsets, fbMsg.WGMemberInfoEnd(builder))
		}
	}

	fbMsg.WGListMembersResponseStartMembersVector(builder, len(memberOffsets))
	for i := len(memberOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(memberOffsets[i])
	}
	membersVectorOffset := builder.EndVector(len(memberOffsets))

	fbMsg.WGListMembersResponseStart(builder)
	fbMsg.WGListMembersResponseAddSuccess(builder, err == nil)
	if err == nil {
		fbMsg.WGListMembersResponseAddMembers(builder, membersVectorOffset)
	} else {
		fbMsg.WGListMembersResponseAddErrorCode(builder, 1)
		fbMsg.WGListMembersResponseAddErrorMessage(builder, errorMsgOffset)
	}
	respBodyOffset := fbMsg.WGListMembersResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_LIST_MEMBERS_ACK)
	fbMsg.MessageHeaderAddSeq(builder, header.Seq())
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGListMembersResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)

	data := builder.FinishedBytes()
	return writeRawMessage(ctx.Conn, data)
}

// HandleCreateSession removed (S5-B2): old session mechanism dead code.

// Method

// PushNetworkEvent 组装 network 级 snapshot 事件，并广播给该网络的所有成员。
// 这是产品级 runtime push 的统一出口，取代旧的 WG_SESSION_STATE 过程消息。
// action 取 fbMsg.WGNetworkEventAction*（UPSERT / DELETE / RUNTIME_UPDATE）。
func (h *WireGuardHandler) PushNetworkEvent(networkID string, action fbMsg.WGNetworkEventAction) error {
	return h.pushNetworkEvent(networkID, action, nil)
}

// A nil member filter broadcasts topology changes to the network. Pair barrier
// progress only invalidates its participants; other members have no pair state
// to consume and must not refetch their whole runtime for each READY/APPLIED.
func (h *WireGuardHandler) pushNetworkEvent(networkID string, action fbMsg.WGNetworkEventAction, members map[string]struct{}) error {
	normalizedID := strings.TrimSpace(networkID)
	if normalizedID == "" {
		return fmt.Errorf("network id is required for push")
	}
	state, epoch := h.runtimeVersions.network(normalizedID)
	state.mu.Lock()
	defer state.mu.Unlock()

	overview, err := h.getNetworkOverview(normalizedID)
	if err != nil {
		return fmt.Errorf("get network overview for push: %w", err)
	}
	revision, err := h.runtimeVersions.advanceLocked(state)
	if err != nil {
		return err
	}
	overview.RevisionEpoch = epoch
	overview.Revision = revision

	// 广播给该网络所有在线成员（仅已连接的 client 会真正收到）。
	// 仅推送给 Online 成员：Active/Leaved/Removed 成员没有 WG 隧道，
	// 不需要接收网络拓扑变更。它们重新上线时会通过 join 流程获取完整 snapshot。
	//
	// 使用异步 ring buffer 广播：消息序列化一次后通过 broadcaster 异步投递，
	// 慢客户端不会阻塞调用方。
	var targetClients []string
	for _, member := range overview.Members {
		if member == nil {
			continue
		}
		if members != nil {
			if _, selected := members[member.ID]; !selected {
				continue
			}
		}
		clientID := strings.TrimSpace(member.ClientID)
		if clientID == "" {
			continue
		}
		if member.Status != MemberStatusOnline && member.Status != MemberStatusActive {
			continue
		}
		if checker, ok := h.sessions.(clientSessionChecker); ok && !checker.HasClientSession(clientID) {
			continue
		}
		targetClients = append(targetClients, clientID)
	}

	if _, recipientAware := h.sessions.(types.CurrentClientSessionReader); !recipientAware {
		// Legacy/test pusher has no authenticated recipient identity.
		data := buildNetworkEventPush(normalizedID, action, epoch, revision, overview, "", "")
		if len(targetClients) > 0 {
			h.sessions.AsyncPushToClients(targetClients, data)
		}
		return nil
	}
	for _, clientID := range targetClients {
		recipient := overview
		userID, deviceID := "", ""
		if controls, ok := h.sessions.(types.CurrentClientSessionReader); ok {
			identity, current := controls.CurrentClientSession(clientID)
			if !current {
				continue
			}
			userID, deviceID = identity.UserID, identity.DeviceID
			ctx := HandlerSession{SessionID: identity.SessionID, UserID: identity.UserID, DeviceID: identity.DeviceID, Hostname: identity.Hostname, Capabilities: identity.Capabilities, ScopeClaims: identity.ScopeClaims}
			var bootstrapErr error
			recipient, bootstrapErr = h.withPathBootstrapResult(ctx, overview)
			if bootstrapErr != nil {
				// Topology is still authoritative; absent authority fences an
				// old writer. Never fabricate a plan when authorization fails.
				logger.Debugf("[PathPush] device=%s network=%s bootstrap deferred: %v", clientID, normalizedID, bootstrapErr)
			}
		}
		data := buildNetworkEventPush(normalizedID, action, epoch, revision, recipient, userID, deviceID)
		h.sessions.AsyncPushToClients([]string{clientID}, data)
	}

	logger.Infof("pushed network event (async): network=%s action=%d members=%d delivered_targets=%d",
		normalizedID, action, len(overview.Members), len(targetClients))

	return nil
}

func buildNetworkEventPush(normalizedID string, action fbMsg.WGNetworkEventAction, epoch string, revision uint64, overview *NetworkOverview, userID, deviceID string) []byte {
	builder := flatbuffers.NewBuilder(1024)
	networkIDOffset := builder.CreateString(normalizedID)
	epochOffset := builder.CreateString(epoch)

	// DELETE 事件不需要完整 snapshot；其余动作附带运行态快照。
	var snapshotOffset flatbuffers.UOffsetT
	includeSnapshot := action != fbMsg.WGNetworkEventActionDELETE
	if includeSnapshot {
		snapshotOffset = buildWGNetworkRuntimeSnapshotOffset(builder, overview, userID, deviceID)
	}

	fbMsg.WGNetworkEventPushStart(builder)
	fbMsg.WGNetworkEventPushAddAction(builder, action)
	fbMsg.WGNetworkEventPushAddNetworkId(builder, networkIDOffset)
	fbMsg.WGNetworkEventPushAddNextRevision(builder, revision)
	fbMsg.WGNetworkEventPushAddRevisionEpoch(builder, epochOffset)
	if includeSnapshot {
		fbMsg.WGNetworkEventPushAddSnapshot(builder, snapshotOffset)
	}
	pushOffset := fbMsg.WGNetworkEventPushEnd(builder)

	sessionStrOffset := builder.CreateString("")
	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_NETWORK_EVENT_PUSH)
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	fbMsg.MessageHeaderAddSessionId(builder, sessionStrOffset)
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGNetworkEventPush)
	fbMsg.MessageAddBody(builder, pushOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	return builder.FinishedBytes()

}

// pushSessionRuntimeUpdate and markSessionFailedAndPushRuntimeUpdate removed (S5-B2).

// createDirectPeerSession removed (S5-B2): old session mechanism dead code.

func selectListedMembers(members []*NetworkMember, onlineOnly bool) []*NetworkMember {
	selected := make([]*NetworkMember, 0, len(members))
	for _, member := range members {
		if member == nil || member.Status == MemberStatusRemoved {
			continue
		}
		if onlineOnly && !memberIsOnline(member) {
			continue
		}
		selected = append(selected, member)
	}
	return selected
}

// sessionHasBidirectionalDirectEndpoints removed (S5-B2).

// PushGatherInfo Push Gathering start notification
func (h *WireGuardHandler) PushGatherInfo(sessionID, clientID string) error {
	return h.pushGatherForNetwork("", sessionID, clientID)
}

func (h *WireGuardHandler) pushGatherForNetwork(networkID, sessionID, clientID string) error {
	// Only LAN gather is supported; non-LAN session gather removed (S5-B2).
	builder := flatbuffers.NewBuilder(256)

	sessionIDOffset := builder.CreateString(sessionID)

	fbMsg.WGGatherInfoStart(builder)
	fbMsg.WGGatherInfoAddSessionId(builder, sessionIDOffset)
	gatherOffset := fbMsg.WGGatherInfoEnd(builder)

	sessionStrOffset := builder.CreateString("")
	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_GATHER_INFO)
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	fbMsg.MessageHeaderAddSessionId(builder, sessionStrOffset)
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGGatherInfo)
	fbMsg.MessageAddBody(builder, gatherOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	data := builder.FinishedBytes()

	return h.sessions.PushToClient(clientID, data)
}

// PushPunchInfo, pushPunchForNetwork, pushPunchMessage, pushPunchMessageForNetwork,
// beginLegacySignal removed (S5-B2): old session mechanism dead code.

// ==================== Gathering Message Processing ====================

// HandleGatherInfo Handle client-reported Gathering information
func (h *WireGuardHandler) HandleGatherInfo(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGGatherInfo
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGGatherInfo body")
	}
	req.Init(table.Bytes, table.Pos)

	sessionID := string(req.SessionId())
	// Use bare deviceID as the canonical clientID — matches what the
	// client sends in all P2P messages (gather, punch).
	fullClientID := ctx.DeviceID

	// LAN gather: sessionID is "lan:<networkID>". Store the LAN endpoint
	// directly without session lookup. The client sends this as fire-and-forget
	// (seq=0), so we do NOT send an ACK — writing back on the connection would
	// race with PushToClient from the maintenance loop and cause ERROR storms.
	if strings.HasPrefix(sessionID, "lan:") {
		networkID := strings.TrimPrefix(sessionID, "lan:")
		localWGEndpoint := strings.TrimSpace(string(req.LocalWgEndpoint()))
		// Collect localAddrs for diagnostic context.
		var lanLocalAddrs []string
		for i := 0; i < req.LocalAddrsLength(); i++ {
			lanLocalAddrs = append(lanLocalAddrs, string(req.LocalAddrs(i)))
		}
		logger.Infof("LAN gather: network=%s client=%s lanEndpoint=%s localAddrs=%v", networkID, fullClientID, localWGEndpoint, lanLocalAddrs)
		if localWGEndpoint != "" && h.coordinator != nil {
			if member, err := h.coordinator.GetClientMember(fullClientID, networkID); err == nil && member != nil {
				// Build candidates: localWGEndpoint first, then remaining localAddrs.
				candidates := buildLANCandidates(localWGEndpoint, lanLocalAddrs)
				if h.coordinator.StoreLANEndpoint(networkID, member.PublicKey, candidates) {
					_ = h.PushNetworkEvent(networkID, fbMsg.WGNetworkEventActionRUNTIME_UPDATE)
				}
			} else {
				logger.Warnf("LAN gather: member lookup failed: clientID=%s network=%s err=%v", fullClientID, networkID, err)
			}
		}
		return nil
	}

	// Non-LAN gather removed (S5-B2): old session mechanism was dead code.
	return nil
}

// HandlePunchInfo removed (S5-B2): old session mechanism dead code.

func (h *WireGuardHandler) HandleUpdateNetworkCIDR(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGUpdateNetworkCIDRRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGUpdateNetworkCIDRRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	header := msg.Header(nil)

	networkID := string(req.NetworkId())
	newCIDR := string(req.NewCidr())

	logger.Infof("handle update network CIDR: network_id=%s, new_cidr=%s", networkID, newCIDR)

	if authErr := h.verifyNetworkOwner(networkID, ctx.UserID); authErr != nil {
		logger.Warnf("update network CIDR denied: network=%s user=%s err=%v", networkID, ctx.UserID, authErr)
		return authErr
	}

	err := h.coordinator.UpdateNetworkCIDR(networkID, newCIDR)

	builder := flatbuffers.NewBuilder(512)
	var networkIDOffset, newCIDROffset, errorMsgOffset flatbuffers.UOffsetT
	if err != nil {
		logger.Errorf("update network CIDR failed: %v", err)
		errorMsgOffset = builder.CreateString(err.Error())
	} else {
		networkIDOffset = builder.CreateString(networkID)
		newCIDROffset = builder.CreateString(newCIDR)
	}

	fbMsg.WGUpdateNetworkCIDRResponseStart(builder)
	fbMsg.WGUpdateNetworkCIDRResponseAddSuccess(builder, err == nil)
	if err == nil {
		fbMsg.WGUpdateNetworkCIDRResponseAddNetworkId(builder, networkIDOffset)
		fbMsg.WGUpdateNetworkCIDRResponseAddNewCidr(builder, newCIDROffset)
	} else {
		fbMsg.WGUpdateNetworkCIDRResponseAddErrorCode(builder, 1)
		fbMsg.WGUpdateNetworkCIDRResponseAddErrorMessage(builder, errorMsgOffset)
	}
	respBodyOffset := fbMsg.WGUpdateNetworkCIDRResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_UPDATE_NETWORK_CIDR_ACK)
	fbMsg.MessageHeaderAddSeq(builder, header.Seq())
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGUpdateNetworkCIDRResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	data := builder.FinishedBytes()

	if writeErr := writeRawMessage(ctx.Conn, data); writeErr != nil {
		return writeErr
	}

	// Detach broadcast from handler goroutine to prevent slow-peer writes
	// from stalling the handleSession read loop.
	if err == nil {
		go func() {
			_ = h.PushNetworkEvent(networkID, fbMsg.WGNetworkEventActionRUNTIME_UPDATE)
		}()
	}
	return nil
}

func (h *WireGuardHandler) HandleUpdateMember(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGUpdateMemberRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGUpdateMemberRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	header := msg.Header(nil)

	networkID := string(req.NetworkId())
	memberID := string(req.MemberId())
	newIP := string(req.NewIp())
	newHostname := string(req.NewHostname())

	logger.Infof("handle update member: network_id=%s, member_id=%s, new_ip=%s, new_hostname=%s", networkID, memberID, newIP, newHostname)

	if authErr := h.verifyNetworkOwner(networkID, ctx.UserID); authErr != nil {
		logger.Warnf("update member denied: network=%s user=%s err=%v", networkID, ctx.UserID, authErr)
		return authErr
	}

	err := h.coordinator.UpdateMember(memberID, newIP, newHostname)

	builder := flatbuffers.NewBuilder(512)
	var networkIDOffset, memberIDOffset, newIPOffset, newHostnameOffset, errorMsgOffset flatbuffers.UOffsetT
	if err != nil {
		logger.Errorf("update member failed: %v", err)
		errorMsgOffset = builder.CreateString(err.Error())
	} else {
		networkIDOffset = builder.CreateString(networkID)
		memberIDOffset = builder.CreateString(memberID)
		newIPOffset = builder.CreateString(newIP)
		newHostnameOffset = builder.CreateString(newHostname)
	}

	fbMsg.WGUpdateMemberResponseStart(builder)
	fbMsg.WGUpdateMemberResponseAddSuccess(builder, err == nil)
	if err == nil {
		fbMsg.WGUpdateMemberResponseAddNetworkId(builder, networkIDOffset)
		fbMsg.WGUpdateMemberResponseAddMemberId(builder, memberIDOffset)
		fbMsg.WGUpdateMemberResponseAddNewIp(builder, newIPOffset)
		fbMsg.WGUpdateMemberResponseAddNewHostname(builder, newHostnameOffset)
	} else {
		fbMsg.WGUpdateMemberResponseAddErrorCode(builder, 1)
		fbMsg.WGUpdateMemberResponseAddErrorMessage(builder, errorMsgOffset)
	}
	respBodyOffset := fbMsg.WGUpdateMemberResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_UPDATE_MEMBER_ACK)
	fbMsg.MessageHeaderAddSeq(builder, header.Seq())
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGUpdateMemberResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	data := builder.FinishedBytes()

	if writeErr := writeRawMessage(ctx.Conn, data); writeErr != nil {
		return writeErr
	}

	// Detach broadcast from handler goroutine.
	if err == nil {
		go func() {
			_ = h.PushNetworkEvent(networkID, fbMsg.WGNetworkEventActionRUNTIME_UPDATE)
		}()
	}
	return nil
}

func (h *WireGuardHandler) HandleUpdateRelayMode(
	ctx HandlerSession,
	msg *fbMsg.Message,
) error {
	var req fbMsg.WGUpdateNetworkRelayModeRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid WGUpdateNetworkRelayModeRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	header := msg.Header(nil)

	networkID := string(req.NetworkId())
	relayMode := RelayModeOptional
	switch req.RelayMode() {
	case fbMsg.WGRelayModeDISABLED:
		relayMode = RelayModeDisabled
	case fbMsg.WGRelayModeFORCE:
		relayMode = RelayModeForce
	}

	logger.Infof("handle update relay mode: network_id=%s, relay_mode=%d", networkID, relayMode)

	if authErr := h.verifyNetworkOwner(networkID, ctx.UserID); authErr != nil {
		logger.Warnf("update relay mode denied: network=%s user=%s err=%v", networkID, ctx.UserID, authErr)
		return authErr
	}

	err := h.coordinator.UpdateRelayMode(networkID, relayMode)

	builder := flatbuffers.NewBuilder(512)
	var networkIDOffset, errorMsgOffset flatbuffers.UOffsetT
	if err != nil {
		logger.Errorf("update relay mode failed: %v", err)
		errorMsgOffset = builder.CreateString(err.Error())
	} else {
		networkIDOffset = builder.CreateString(networkID)
	}

	fbRelayMode := fbMsg.WGRelayModeOPTIONAL
	switch relayMode {
	case RelayModeDisabled:
		fbRelayMode = fbMsg.WGRelayModeDISABLED
	case RelayModeForce:
		fbRelayMode = fbMsg.WGRelayModeFORCE
	}

	fbMsg.WGUpdateNetworkRelayModeResponseStart(builder)
	fbMsg.WGUpdateNetworkRelayModeResponseAddSuccess(builder, err == nil)
	if err == nil {
		fbMsg.WGUpdateNetworkRelayModeResponseAddNetworkId(builder, networkIDOffset)
		fbMsg.WGUpdateNetworkRelayModeResponseAddRelayMode(builder, fbRelayMode)
	} else {
		fbMsg.WGUpdateNetworkRelayModeResponseAddErrorCode(builder, 1)
		fbMsg.WGUpdateNetworkRelayModeResponseAddErrorMessage(builder, errorMsgOffset)
	}
	respBodyOffset := fbMsg.WGUpdateNetworkRelayModeResponseEnd(builder)

	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeWG_UPDATE_NETWORK_RELAY_MODE_ACK)
	fbMsg.MessageHeaderAddSeq(builder, header.Seq())
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(getNowMillis()))
	headerOffset := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, headerOffset)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyWGUpdateNetworkRelayModeResponse)
	fbMsg.MessageAddBody(builder, respBodyOffset)
	msgOffset := fbMsg.MessageEnd(builder)

	builder.Finish(msgOffset)
	data := builder.FinishedBytes()

	if writeErr := writeRawMessage(ctx.Conn, data); writeErr != nil {
		return writeErr
	}

	// Detach broadcast from handler goroutine.
	if err == nil {
		go func() {
			_ = h.PushNetworkEvent(networkID, fbMsg.WGNetworkEventActionRUNTIME_UPDATE)
		}()
	}
	return nil
}

// filterLANEndpointsForRequester finds the requesting client's member public key
// and returns same-NAT-filtered LAN endpoint candidates. Falls back to the full
// map when the requester cannot be identified (e.g. not yet joined).
func (h *WireGuardHandler) filterLANEndpointsForRequester(overview *NetworkOverview, networkID, clientID string) map[string][]string {
	if overview == nil || h.coordinator == nil {
		return nil
	}
	for _, member := range overview.Members {
		if member != nil && member.ClientID == clientID && hasRealPublicKey(member) {
			filtered := h.coordinator.GetLANPeerEndpointCandidatesForClient(networkID, member.PublicKey)
			if filtered != nil {
				return filtered
			}
			break
		}
	}
	// Requester not found or has no public key yet; return full map as fallback.
	return overview.LANPeerEndpoints
}

// resolveMemberClientID finds the canonical clientID (userID-deviceID) for a
// bare deviceID by scanning the network's members.  Falls back to composing
// userID-deviceID when the member is not found (e.g. not yet joined).
func resolveMemberClientID(
	coord HandlerCoordinator,
	networkID, bareDeviceID, userID string,
) string {
	if coord == nil || networkID == "" || bareDeviceID == "" {
		return userID + "-" + bareDeviceID
	}
	suffix := "-" + bareDeviceID
	for _, member := range coord.ListNetworkMembers(networkID) {
		if member != nil && strings.HasSuffix(member.ClientID, suffix) {
			return member.ClientID
		}
	}
	// Member not found yet; compose from known userID.
	return userID + "-" + bareDeviceID
}

// buildLANCandidates constructs the candidate list from the primary WG endpoint
// and the raw localAddrs reported by the client. The primary endpoint (IP:PORT)
// is always first. Additional localAddrs are appended with the same port,
// skipping duplicates and the primary IP.
func buildLANCandidates(primaryWGEndpoint string, localAddrs []string) []string {
	primaryIP, primaryPort, splitErr := net.SplitHostPort(primaryWGEndpoint)
	if splitErr != nil || primaryIP == "" || primaryPort == "" {
		// Fallback: just return the primary as-is.
		if primaryWGEndpoint != "" {
			return []string{primaryWGEndpoint}
		}
		return nil
	}
	seen := map[string]bool{primaryIP: true}
	candidates := []string{primaryWGEndpoint}
	for _, addr := range localAddrs {
		addr = strings.TrimSpace(addr)
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		candidates = append(candidates, net.JoinHostPort(addr, primaryPort))
	}
	return candidates
}
