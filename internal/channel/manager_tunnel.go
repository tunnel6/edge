package channel

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	p2p "icool.io/yat/edge/internal/channel/p2p"
	"icool.io/yat/edge/internal/tunnelpolicy"
	logger "icool.io/yat/edge/pkg/log"
)

type tunnelStartConfig struct {
	RemotePort         uint16   `json:"remote_port,omitempty"`
	EagerConnectRemote bool     `json:"eager_connect_remote,omitempty"`
	ActorRole          uint8    `json:"actor_role,omitempty"`
	ActorSessionID     string   `json:"actor_session_id,omitempty"`
	ActorDeviceID      string   `json:"actor_device_id,omitempty"`
	LinkType           string   `json:"link_type,omitempty"`
	PreferredLinks     []string `json:"preferred_links,omitempty"`
	AllowRelayFallback bool     `json:"allow_relay_fallback,omitempty"`
	RequireDirect      bool     `json:"require_direct,omitempty"`
}

type tunnelLinkPolicy struct {
	LinkType           string
	PreferredLinks     []string
	AllowRelayFallback bool
	RequireDirect      bool
}

type tunnelLinkPolicyOverride struct {
	LinkType           string   `json:"link_type,omitempty"`
	Preferred          []string `json:"preferred,omitempty"`
	PreferredLinks     []string `json:"preferred_links,omitempty"`
	AllowRelayFallback *bool    `json:"allow_relay_fallback,omitempty"`
	RequireDirect      *bool    `json:"require_direct,omitempty"`
}

type tunnelMetadataLinkPolicyEnvelope struct {
	LinkPolicy *tunnelLinkPolicyOverride `json:"link_policy,omitempty"`

	LinkType           string   `json:"link_type,omitempty"`
	Preferred          []string `json:"preferred,omitempty"`
	PreferredLinks     []string `json:"preferred_links,omitempty"`
	AllowRelayFallback *bool    `json:"allow_relay_fallback,omitempty"`
	RequireDirect      *bool    `json:"require_direct,omitempty"`
}

type tunnelMetadataSubdomainEnvelope struct {
	Subdomain string `json:"subdomain,omitempty"`
}

type tunnelSubdomainResolveSource string

const (
	tunnelSubdomainResolveSourceNone     tunnelSubdomainResolveSource = "none"
	tunnelSubdomainResolveSourceField    tunnelSubdomainResolveSource = "field"
	tunnelSubdomainResolveSourceMetadata tunnelSubdomainResolveSource = "metadata"
)

type tunnelJoinSubdomainHintSourceCounts struct {
	field    uint64
	metadata uint64
	none     uint64
}

type tunnelSubdomainResolutionCounters struct {
	startTotal               uint64
	startField               uint64
	startMetadataFallback    uint64
	startNone                uint64
	joinHintTotal            uint64
	joinHintField            uint64
	joinHintMetadataFallback uint64
	joinHintNone             uint64
	joinHintMismatch         uint64
	updatedAtUnix            int64
}

type tunnelRuntimeChannelView struct {
	ID                 string   `json:"id"`
	Key                string   `json:"key,omitempty"`
	Protocol           string   `json:"protocol,omitempty"`
	LinkType           string   `json:"link_type,omitempty"`
	PreferredLinks     []string `json:"preferred_links,omitempty"`
	AllowRelayFallback bool     `json:"allow_relay_fallback,omitempty"`
	RequireDirect      bool     `json:"require_direct,omitempty"`
	Type               string   `json:"type,omitempty"`
	LocalAddr          string   `json:"local_addr,omitempty"`
	RemoteEndpoint     string   `json:"remote_endpoint,omitempty"`
	AssignedDomain     string   `json:"assigned_domain,omitempty"`
	AliasDomain        string   `json:"alias_domain,omitempty"`
	State              string   `json:"state,omitempty"`
	SessionID          string   `json:"session_id,omitempty"`
	UserID             string   `json:"user_id,omitempty"`
	DeviceID           string   `json:"device_id,omitempty"`
	Hostname           string   `json:"hostname,omitempty"`
	ActorRole          string   `json:"actor_role,omitempty"`
	ActorSessionID     string   `json:"actor_session_id,omitempty"`
	ActorDeviceID      string   `json:"actor_device_id,omitempty"`
	ActorHostname      string   `json:"actor_hostname,omitempty"`
	Port               uint16   `json:"port,omitempty"`
}

type tunnelRuntimeSnapshotView struct {
	TunnelID    string                     `json:"tunnel_id"`
	ChannelIDs  []string                   `json:"channel_ids"`
	ChannelKeys []string                   `json:"channel_keys"`
	Channels    []tunnelRuntimeChannelView `json:"channels"`
	Peers       []tunnelRuntimePeerView    `json:"peers,omitempty"`
}

type tunnelRuntimePeerView struct {
	ID                 string   `json:"id"`
	NetworkID          string   `json:"network_id,omitempty"`
	InitiatorID        string   `json:"initiator_id,omitempty"`
	PeerA              string   `json:"peer_a,omitempty"`
	PeerB              string   `json:"peer_b,omitempty"`
	Status             string   `json:"status"`
	PathState          string   `json:"path_state,omitempty"`
	PathType           string   `json:"path_type,omitempty"`
	LinkType           string   `json:"link_type,omitempty"`
	PreferredLinks     []string `json:"preferred_links,omitempty"`
	AllowRelayFallback bool     `json:"allow_relay_fallback,omitempty"`
	RequireDirect      bool     `json:"require_direct,omitempty"`
	LastError          string   `json:"last_error,omitempty"`
	CreatedAt          int64    `json:"created_at,omitempty"`
	UpdatedAt          int64    `json:"updated_at,omitempty"`
}

type selectedTunnelChannel struct {
	Key       string
	ChannelID string
}

// TunnelObservedChannel carries edge-authoritative runtime path fields for one
// channel under a tunnel. It is intentionally minimal and used by upper-layer
// coordination code (for example tunnel definition upsert normalization).
type TunnelObservedChannel struct {
	ChannelID      string
	ChannelKey     string
	LinkType       string
	RemoteEndpoint string
	ActorRole      uint8
	SessionID      string
	ActorSessionID string
	ActorDeviceID  string
	DeviceID       string
	State          string
}

const tunnelStartRevisionConflictCode uint32 = 409

func (m *ChannelManager) HandleTunnelStart(ctx *HandlerContext, msg *fbMsg.Message) error {
	req, err := safeParseTunnelStartRequest(msg)
	if err != nil {
		logger.Errorf("failed to parse tunnel start request: %v", err)
		return ctx.Protocol.SendTunnelStartResponse(ctx.Conn, &fbMsg.TunnelStartResponseT{
			Success:      false,
			Mode:         fbMsg.TunnelStartModeALL_OR_NOTHING,
			ErrorCode:    uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			ErrorMessage: fmt.Sprintf("invalid message format: %v", err),
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	tunnelID := strings.TrimSpace(string(req.TunnelId()))
	edgeID := strings.TrimSpace(string(req.EdgeId()))
	mode := normalizeTunnelStartMode(req.Mode())
	actorRole, actorSessionID, actorDeviceID, actorCode, actorMessage := resolveTunnelActorContext(req.Actor(nil))
	if actorCode != 0 {
		return ctx.Protocol.SendTunnelStartResponse(ctx.Conn, &fbMsg.TunnelStartResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(actorCode),
			ErrorMessage: actorMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}
	allOrNothing := mode == fbMsg.TunnelStartModeALL_OR_NOTHING
	if actorRole != fbMsg.TunnelActorRolePUBLISHER {
		return ctx.Protocol.SendTunnelStartResponse(ctx.Conn, &fbMsg.TunnelStartResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(fbMsg.ErrorCodeAUTH_FAILED),
			ErrorMessage: "start requires publisher actor role",
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	if tunnelID == "" {
		return ctx.Protocol.SendTunnelStartResponse(ctx.Conn, &fbMsg.TunnelStartResponseT{
			Success:      false,
			Mode:         mode,
			EdgeId:       edgeID,
			ErrorCode:    uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			ErrorMessage: "missing tunnel_id",
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}
	if syncedEdgeID, precheckCode, precheckMessage := m.upsertTunnelDefinitionBeforeStart(
		ctx,
		req,
		tunnelID,
		edgeID,
	); precheckCode != 0 {
		return ctx.Protocol.SendTunnelStartResponse(ctx.Conn, &fbMsg.TunnelStartResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    precheckCode,
			ErrorMessage: precheckMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	} else if strings.TrimSpace(syncedEdgeID) != "" {
		edgeID = strings.TrimSpace(syncedEdgeID)
	}
	verifiedEdgeID, verifyCode, verifyMessage := m.verifyTunnelRuntimeOwnership(ctx.UserID, edgeID, tunnelID)
	if verifyCode != 0 {
		return ctx.Protocol.SendTunnelStartResponse(ctx.Conn, &fbMsg.TunnelStartResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(verifyCode),
			ErrorMessage: verifyMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}
	edgeID = verifiedEdgeID
	if rejectCode, rejectMessage := m.validateTunnelActorContext(
		ctx.UserID,
		edgeID,
		tunnelID,
		actorRole,
		ctx.DeviceID,
	); rejectCode != 0 {
		return ctx.Protocol.SendTunnelStartResponse(ctx.Conn, &fbMsg.TunnelStartResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(rejectCode),
			ErrorMessage: rejectMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	channelTotal := req.ChannelsLength()
	results := make([]*fbMsg.TunnelChannelStartResultT, 0, channelTotal)
	createdIDs := make([]string, 0, channelTotal)
	reconnectCleaned := false

	var firstErrorMessage string
	var firstErrorCode uint32

	appendFailureResult := func(key, channelID string, code fbMsg.ErrorCode, message string, negotiatedBufferSize uint32) *fbMsg.TunnelChannelStartResultT {
		res := &fbMsg.TunnelChannelStartResultT{
			Key:                  strings.TrimSpace(key),
			ChannelId:            strings.TrimSpace(channelID),
			Success:              false,
			ErrorCode:            uint32(code),
			ErrorMessage:         strings.TrimSpace(message),
			NegotiatedBufferSize: negotiatedBufferSize,
		}
		if firstErrorMessage == "" {
			firstErrorMessage = res.ErrorMessage
			firstErrorCode = res.ErrorCode
		}
		results = append(results, res)
		return res
	}

	rollbackMarked := false
	if req.Reconnect() {
		reconnectTargets := m.selectTunnelChannelsForStartReconnect(
			tunnelID,
			readTunnelStartKeys(req),
			actorRole,
			actorSessionID,
			actorDeviceID,
		)
		for _, item := range reconnectTargets {
			if err := m.Close(item.ChannelID); err != nil {
				logger.Warnf("reconnect cleanup failed, tunnel=%s, key=%s, channel=%s, err=%v", tunnelID, item.Key, item.ChannelID, err)
				if allOrNothing {
					failureMessage := fmt.Sprintf("reconnect cleanup failed for key %s: %v", item.Key, err)
					summary := &fbMsg.TunnelOperationSummaryT{
						Requested: uint32(channelTotal),
						Failed:    uint32(channelTotal),
					}
					return ctx.Protocol.SendTunnelStartResponse(ctx.Conn, &fbMsg.TunnelStartResponseT{
						Success:      false,
						Mode:         mode,
						TunnelId:     tunnelID,
						EdgeId:       edgeID,
						Summary:      summary,
						ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
						ErrorMessage: failureMessage,
					}, ctx.SessionID)
				}
				continue
			}
			reconnectCleaned = true
		}
	}

	seenKeys := make(map[string]struct{}, channelTotal)

	for i := 0; i < channelTotal; i++ {
		var spec fbMsg.TunnelChannelStartSpec
		if !req.Channels(&spec, i) {
			appendFailureResult(
				fmt.Sprintf("channel-%d", i+1),
				"",
				fbMsg.ErrorCodeINVALID_MESSAGE,
				"invalid channel spec",
				0,
			)
			if allOrNothing {
				break
			}
			continue
		}

		key := strings.TrimSpace(string(spec.Key()))
		if key == "" {
			key = fmt.Sprintf("channel-%d", i+1)
			appendFailureResult(
				key,
				"",
				fbMsg.ErrorCodeINVALID_MESSAGE,
				"missing channel key",
				spec.BufferSize(),
			)
			if allOrNothing {
				break
			}
			continue
		}
		if _, duplicated := seenKeys[key]; duplicated {
			appendFailureResult(
				key,
				composeTunnelChannelID(tunnelID, key),
				fbMsg.ErrorCodeINVALID_MESSAGE,
				fmt.Sprintf("duplicate channel key: %s", key),
				spec.BufferSize(),
			)
			if allOrNothing {
				break
			}
			continue
		}
		seenKeys[key] = struct{}{}

		protocol := strings.ToLower(strings.TrimSpace(string(spec.Protocol())))
		channelType, ok := inferChannelTypeFromProtocolStrict(protocol)
		channelID := composeTunnelChannelIDForActor(tunnelID, key, actorRole, actorSessionID, actorDeviceID)
		if !ok {
			appendFailureResult(
				key,
				channelID,
				fbMsg.ErrorCodeINVALID_MESSAGE,
				fmt.Sprintf("unsupported protocol: %s", protocol),
				spec.BufferSize(),
			)
			if allOrNothing {
				break
			}
			continue
		}
		if !isProtocolAllowedByCapabilities(protocol, ctx.Capabilities) {
			appendFailureResult(
				key,
				channelID,
				fbMsg.ErrorCodeAUTH_FAILED,
				capabilityViolationMessage(protocol),
				spec.BufferSize(),
			)
			if allOrNothing {
				break
			}
			continue
		}

		localPort := spec.LocalPort()
		if localPort == 0 {
			appendFailureResult(
				key,
				channelID,
				fbMsg.ErrorCodeINVALID_MESSAGE,
				"missing local_port",
				spec.BufferSize(),
			)
			if allOrNothing {
				break
			}
			continue
		}

		if err := m.EnsureForChannelType(channelType); err != nil {
			appendFailureResult(
				key,
				channelID,
				fbMsg.ErrorCodeINTERNAL_ERROR,
				err.Error(),
				spec.BufferSize(),
			)
			if allOrNothing {
				break
			}
			continue
		}

		linkPolicy := resolveTunnelLinkPolicy(string(spec.Transport()), string(spec.MetadataJson()))
		subdomain, subdomainSource := resolveTunnelStartSubdomainWithSource(&spec)
		m.recordTunnelStartSubdomainResolution(subdomainSource)
		logger.Debugf("[ICE] tunnel start channel: tunnel=%s key=%s transport=%q metadataJson=%q resolved linkType=%s subdomain=%q subdomainSource=%s",
			tunnelID, key, string(spec.Transport()), string(spec.MetadataJson()), linkPolicy.LinkType, subdomain, subdomainSource)
		createReq := &CreateRequest{
			ID:                 channelID,
			Type:               channelType,
			SessionID:          ctx.SessionID,
			UserID:             ctx.UserID,
			DeviceID:           ctx.DeviceID,
			DeviceHostname:     strings.TrimSpace(ctx.Hostname),
			ActorRole:          actorRole,
			ActorSessionID:     actorSessionID,
			ActorDeviceID:      actorDeviceID,
			ActorHostname:      strings.TrimSpace(ctx.Hostname),
			LocalAddr:          buildLocalAddr(string(spec.LocalHost()), localPort),
			Subdomain:          subdomain,
			AliasDomain:        strings.TrimSpace(string(spec.AliasDomain())),
			RemotePort:         spec.RemotePort(),
			EagerConnectRemote: spec.EagerConnectRemote(),
			ChannelKey:         key,
			Protocol:           protocol,
			LinkType:           linkPolicy.LinkType,
			PreferredLinks:     append([]string(nil), linkPolicy.PreferredLinks...),
			AllowRelayFallback: linkPolicy.AllowRelayFallback,
			RequireDirect:      linkPolicy.RequireDirect,
			ConnRemoteAddr:     connRemoteAddrFromCtx(ctx),
		}

		// Enforce alias domain policy (only applicable to HTTP/HTTPS channels).
		if msg, ok := validateAliasDomainPolicy(m.aliasDomainPolicy(), channelType, createReq.AliasDomain); !ok {
			appendFailureResult(
				key,
				channelID,
				fbMsg.ErrorCodeINVALID_MESSAGE,
				msg,
				spec.BufferSize(),
			)
			if allOrNothing {
				break
			}
			continue
		}

		createResult, createErr := m.Create(createReq)
		if createErr != nil {
			appendFailureResult(
				key,
				channelID,
				fbMsg.ErrorCodeINTERNAL_ERROR,
				createErr.Error(),
				spec.BufferSize(),
			)
			if allOrNothing {
				break
			}
			continue
		}
		if createResult == nil {
			appendFailureResult(
				key,
				channelID,
				fbMsg.ErrorCodeINTERNAL_ERROR,
				"channel create returned nil result",
				spec.BufferSize(),
			)
			if allOrNothing {
				break
			}
			continue
		}
		if !createResult.Success {
			errorCode := createResult.ErrorCode
			if errorCode == 0 {
				errorCode = uint32(fbMsg.ErrorCodeINTERNAL_ERROR)
			}
			appendFailureResult(
				key,
				channelID,
				fbMsg.ErrorCode(errorCode),
				createResult.ErrorMessage,
				spec.BufferSize(),
			)
			if allOrNothing {
				break
			}
			continue
		}
		if actorRole == fbMsg.TunnelActorRolePUBLISHER &&
			(channelType == fbMsg.ChannelTypeTCP || channelType == fbMsg.ChannelTypeUDP) &&
			!remoteEndpointHasPort(createResult.RemoteEndpoint) {
			if closeErr := m.Close(channelID); closeErr != nil {
				logger.Warnf("rollback channel after missing remote endpoint failed, channel=%s, err=%v", channelID, closeErr)
			}
			appendFailureResult(
				key,
				channelID,
				fbMsg.ErrorCodeINTERNAL_ERROR,
				fmt.Sprintf("channel create missing remote endpoint with port: %s", createResult.RemoteEndpoint),
				spec.BufferSize(),
			)
			if allOrNothing {
				break
			}
			continue
		}

		ackAliasDomain := createResult.AliasDomain
		ackCustomDomain := ""
		ackAssignedDomain := createResult.Domain
		ackRemoteEndpoint := createResult.RemoteEndpoint
		ackErrorMessage := ""

		if ackBuilder := m.createAckBuilders[channelType]; ackBuilder != nil {
			configRaw := buildTunnelStartConfigRaw(spec, actorRole, actorSessionID, actorDeviceID, linkPolicy)
			var ackErr error
			ackAliasDomain, ackCustomDomain, ackAssignedDomain, ackRemoteEndpoint, ackErrorMessage, ackErr = ackBuilder.BuildChannelCreateAck(
				channelType,
				configRaw,
				createReq,
				createResult,
			)
			if ackErr != nil {
				if closeErr := m.Close(channelID); closeErr != nil {
					logger.Warnf("rollback channel after tunnel start ack error failed, channel=%s, err=%v", channelID, closeErr)
				}
				appendFailureResult(
					key,
					channelID,
					fbMsg.ErrorCodeINTERNAL_ERROR,
					ackErr.Error(),
					spec.BufferSize(),
				)
				if allOrNothing {
					break
				}
				continue
			}
		}
		if actorRole == fbMsg.TunnelActorRolePUBLISHER &&
			(channelType == fbMsg.ChannelTypeTCP || channelType == fbMsg.ChannelTypeUDP) &&
			!remoteEndpointHasPort(ackRemoteEndpoint) {
			if closeErr := m.Close(channelID); closeErr != nil {
				logger.Warnf("rollback channel after invalid ack remote endpoint failed, channel=%s, err=%v", channelID, closeErr)
			}
			appendFailureResult(
				key,
				channelID,
				fbMsg.ErrorCodeINTERNAL_ERROR,
				fmt.Sprintf("channel ack missing remote endpoint with port: %s", ackRemoteEndpoint),
				spec.BufferSize(),
			)
			if allOrNothing {
				break
			}
			continue
		}

		results = append(results, &fbMsg.TunnelChannelStartResultT{
			Key:                  key,
			ChannelId:            channelID,
			Success:              true,
			RemoteEndpoint:       ackRemoteEndpoint,
			AliasDomain:          ackAliasDomain,
			CustomDomain:         ackCustomDomain,
			AssignedDomain:       ackAssignedDomain,
			ErrorMessage:         ackErrorMessage,
			NegotiatedBufferSize: spec.BufferSize(),
		})
		createdIDs = append(createdIDs, channelID)
	}

	if allOrNothing {
		hasFailure := false
		for _, item := range results {
			if item == nil || item.Success {
				continue
			}
			hasFailure = true
			break
		}
		if hasFailure {
			reason := firstErrorMessage
			if reason == "" {
				reason = "tunnel start failed"
			}
			for i := len(createdIDs) - 1; i >= 0; i-- {
				if err := m.Close(createdIDs[i]); err != nil {
					logger.Warnf("rollback created channel failed, channel=%s, err=%v", createdIDs[i], err)
				}
			}
			for _, item := range results {
				if item == nil || !item.Success {
					continue
				}
				item.Success = false
				item.ErrorCode = uint32(fbMsg.ErrorCodeINTERNAL_ERROR)
				item.ErrorMessage = fmt.Sprintf("rolled back due to all-or-nothing failure: %s", reason)
				item.RemoteEndpoint = ""
				item.AliasDomain = ""
				item.CustomDomain = ""
				item.AssignedDomain = ""
			}
			rollbackMarked = true
		}
	}

	if len(results) < channelTotal {
		for i := len(results); i < channelTotal; i++ {
			var spec fbMsg.TunnelChannelStartSpec
			key := fmt.Sprintf("channel-%d", i+1)
			channelID := ""
			bufferSize := uint32(0)
			if req.Channels(&spec, i) {
				if trimmed := strings.TrimSpace(string(spec.Key())); trimmed != "" {
					key = trimmed
					channelID = composeTunnelChannelID(tunnelID, key)
				}
				bufferSize = spec.BufferSize()
			}
			appendFailureResult(
				key,
				channelID,
				fbMsg.ErrorCodeINTERNAL_ERROR,
				"skipped due to previous failure",
				bufferSize,
			)
		}
	}

	summary := summarizeTunnelStartResults(results)
	success := resolveTunnelOperationSuccess(mode, summary)
	if !success && firstErrorCode == 0 {
		firstErrorCode = uint32(fbMsg.ErrorCodeINTERNAL_ERROR)
	}

	if m.statusMgr != nil && (summary.Succeeded > 0 || rollbackMarked || reconnectCleaned) {
		m.statusMgr.NotifyStatusChange()
	}

	if summary.Succeeded > 0 || rollbackMarked || reconnectCleaned {
		if err := m.persistTunnelRuntimeSnapshot(tunnelID); err != nil {
			logger.Warnf("persist tunnel runtime snapshot after start failed, tunnel=%s, err=%v", tunnelID, err)
		}
	}

	resp := &fbMsg.TunnelStartResponseT{
		Success:         success,
		Mode:            mode,
		TunnelId:        tunnelID,
		EdgeId:          edgeID,
		Summary:         summary,
		Channels:        results,
		RuntimeSnapshot: m.buildTunnelRuntimeSnapshot(tunnelID),
		ErrorCode:       firstErrorCode,
		ErrorMessage:    firstErrorMessage,
	}
	if success {
		resp.ErrorCode = 0
		resp.ErrorMessage = ""
		m.maybeStartICE(tunnelID)
	}

	return ctx.Protocol.SendTunnelStartResponse(ctx.Conn, resp, ctx.SessionID)
}

func (m *ChannelManager) HandleTunnelStop(ctx *HandlerContext, msg *fbMsg.Message) error {
	req, err := safeParseTunnelStopRequest(msg)
	if err != nil {
		logger.Errorf("failed to parse tunnel stop request: %v", err)
		return ctx.Protocol.SendTunnelStopResponse(ctx.Conn, &fbMsg.TunnelStopResponseT{
			Success:      false,
			Mode:         fbMsg.TunnelStartModeALL_OR_NOTHING,
			ErrorCode:    uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			ErrorMessage: fmt.Sprintf("invalid message format: %v", err),
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	tunnelID := strings.TrimSpace(string(req.TunnelId()))
	edgeID := strings.TrimSpace(string(req.EdgeId()))
	mode := normalizeTunnelStartMode(req.Mode())
	actorRole, _, _, actorCode, actorMessage := resolveTunnelActorContext(req.Actor(nil))
	if actorCode != 0 {
		return ctx.Protocol.SendTunnelStopResponse(ctx.Conn, &fbMsg.TunnelStopResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(actorCode),
			ErrorMessage: actorMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}
	if actorRole != fbMsg.TunnelActorRolePUBLISHER {
		return ctx.Protocol.SendTunnelStopResponse(ctx.Conn, &fbMsg.TunnelStopResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(fbMsg.ErrorCodeAUTH_FAILED),
			ErrorMessage: "stop requires publisher actor role",
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	if tunnelID == "" {
		return ctx.Protocol.SendTunnelStopResponse(ctx.Conn, &fbMsg.TunnelStopResponseT{
			Success:      false,
			Mode:         mode,
			EdgeId:       edgeID,
			ErrorCode:    uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			ErrorMessage: "missing tunnel_id",
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}
	verifiedEdgeID, verifyCode, verifyMessage := m.verifyTunnelRuntimeOwnership(ctx.UserID, edgeID, tunnelID)
	if verifyCode != 0 {
		return ctx.Protocol.SendTunnelStopResponse(ctx.Conn, &fbMsg.TunnelStopResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(verifyCode),
			ErrorMessage: verifyMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}
	edgeID = verifiedEdgeID
	if rejectCode, rejectMessage := m.validateTunnelActorContext(
		ctx.UserID,
		edgeID,
		tunnelID,
		actorRole,
		ctx.DeviceID,
	); rejectCode != 0 {
		return ctx.Protocol.SendTunnelStopResponse(ctx.Conn, &fbMsg.TunnelStopResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(rejectCode),
			ErrorMessage: rejectMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	tunnelTargets := m.listTunnelTargets(tunnelID)
	results := make([]*fbMsg.TunnelChannelStopResultT, 0)
	var selected []selectedTunnelChannel
	keys := readTunnelStopKeys(req)

	if len(keys) == 0 {
		selected = make([]selectedTunnelChannel, 0, len(tunnelTargets))
		for channelID, target := range tunnelTargets {
			selected = append(selected, selectedTunnelChannel{
				Key:       resolveTunnelChannelKey(tunnelID, channelID, target),
				ChannelID: channelID,
			})
		}
		sort.Slice(selected, func(i, j int) bool {
			return selected[i].ChannelID < selected[j].ChannelID
		})
	} else {
		seen := make(map[string]struct{}, len(keys))
		for _, key := range keys {
			if key == "" {
				continue
			}
			channelID, ok := findTunnelChannelIDByKey(tunnelID, key, tunnelTargets)
			if !ok {
				results = append(results, &fbMsg.TunnelChannelStopResultT{
					Key:          key,
					ChannelId:    composeTunnelChannelID(tunnelID, key),
					Success:      false,
					ErrorCode:    uint32(fbMsg.ErrorCodeCHANNEL_NOT_FOUND),
					ErrorMessage: "channel not found",
				})
				continue
			}
			if _, dup := seen[channelID]; dup {
				continue
			}
			seen[channelID] = struct{}{}
			selected = append(selected, selectedTunnelChannel{
				Key:       key,
				ChannelID: channelID,
			})
		}
	}

	closedAny := false
	stoppedTargets := make([]*Channel, 0, len(selected))
	var firstErrorMessage string
	var firstErrorCode uint32
	for _, item := range selected {
		target := tunnelTargets[item.ChannelID]
		closeErr := m.Close(item.ChannelID)
		if closeErr != nil {
			results = append(results, &fbMsg.TunnelChannelStopResultT{
				Key:          item.Key,
				ChannelId:    item.ChannelID,
				Success:      false,
				ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
				ErrorMessage: closeErr.Error(),
			})
			if firstErrorMessage == "" {
				firstErrorMessage = closeErr.Error()
				firstErrorCode = uint32(fbMsg.ErrorCodeINTERNAL_ERROR)
			}
			continue
		}
		closedAny = true
		if target != nil {
			stoppedTargets = append(stoppedTargets, target)
		}
		results = append(results, &fbMsg.TunnelChannelStopResultT{
			Key:       item.Key,
			ChannelId: item.ChannelID,
			Success:   true,
		})
	}

	if closedAny {
		m.maybeStopICEForStoppedTunnelTargets(tunnelID, stoppedTargets)
	}

	summary := summarizeTunnelStopResults(results)
	success := resolveTunnelOperationSuccess(mode, summary)

	if m.statusMgr != nil && closedAny {
		m.statusMgr.NotifyStatusChange()
	}
	if closedAny {
		if err := m.persistTunnelRuntimeSnapshot(tunnelID); err != nil {
			logger.Warnf("persist tunnel runtime snapshot after stop failed, tunnel=%s, err=%v", tunnelID, err)
		}
	}

	resp := &fbMsg.TunnelStopResponseT{
		Success:         success,
		Mode:            mode,
		TunnelId:        tunnelID,
		EdgeId:          edgeID,
		Summary:         summary,
		Channels:        results,
		RuntimeSnapshot: m.buildTunnelRuntimeSnapshot(tunnelID),
		ErrorCode:       firstErrorCode,
		ErrorMessage:    firstErrorMessage,
	}
	if success {
		resp.ErrorCode = 0
		resp.ErrorMessage = ""
	}

	return ctx.Protocol.SendTunnelStopResponse(ctx.Conn, resp, ctx.SessionID)
}

func (m *ChannelManager) HandleTunnelJoin(ctx *HandlerContext, msg *fbMsg.Message) error {
	req, err := safeParseTunnelJoinRequest(msg)
	if err != nil {
		logger.Errorf("failed to parse tunnel join request: %v", err)
		return ctx.Protocol.SendTunnelJoinResponse(ctx.Conn, &fbMsg.TunnelJoinResponseT{
			Success:      false,
			Mode:         fbMsg.TunnelStartModeALL_OR_NOTHING,
			ErrorCode:    uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			ErrorMessage: fmt.Sprintf("invalid message format: %v", err),
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	tunnelID := strings.TrimSpace(string(req.TunnelId()))
	edgeID := strings.TrimSpace(string(req.EdgeId()))
	mode := normalizeTunnelStartMode(req.Mode())
	actorRole, _, _, actorCode, actorMessage := resolveTunnelActorContext(req.Actor(nil))
	if actorCode != 0 {
		return ctx.Protocol.SendTunnelJoinResponse(ctx.Conn, &fbMsg.TunnelJoinResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(actorCode),
			ErrorMessage: actorMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}
	allOrNothing := mode == fbMsg.TunnelStartModeALL_OR_NOTHING

	if actorRole == fbMsg.TunnelActorRolePUBLISHER {
		return ctx.Protocol.SendTunnelJoinResponse(ctx.Conn, &fbMsg.TunnelJoinResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(fbMsg.ErrorCodeAUTH_FAILED),
			ErrorMessage: "join requires consumer/controller actor role",
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	if tunnelID == "" {
		return ctx.Protocol.SendTunnelJoinResponse(ctx.Conn, &fbMsg.TunnelJoinResponseT{
			Success:      false,
			Mode:         mode,
			EdgeId:       edgeID,
			ErrorCode:    uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			ErrorMessage: "missing tunnel_id",
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}
	verifiedEdgeID, verifyCode, verifyMessage := m.verifyTunnelRuntimeOwnership(ctx.UserID, edgeID, tunnelID)
	if verifyCode != 0 {
		return ctx.Protocol.SendTunnelJoinResponse(ctx.Conn, &fbMsg.TunnelJoinResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(verifyCode),
			ErrorMessage: verifyMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}
	edgeID = verifiedEdgeID
	if rejectCode, rejectMessage := m.validateTunnelActorContext(
		ctx.UserID,
		edgeID,
		tunnelID,
		actorRole,
		ctx.DeviceID,
	); rejectCode != 0 {
		return ctx.Protocol.SendTunnelJoinResponse(ctx.Conn, &fbMsg.TunnelJoinResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(rejectCode),
			ErrorMessage: rejectMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	channelTotal := req.ChannelsLength()
	tunnelTargets := m.listTunnelTargets(tunnelID)
	if _, ok := resolveActiveP2PPublisherClientID(tunnelID, tunnelTargets); !ok {
		return ctx.Protocol.SendTunnelJoinResponse(ctx.Conn, &fbMsg.TunnelJoinResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(fbMsg.ErrorCodeP2P_NOT_ENABLED),
			ErrorMessage: "tunnel does not enable active p2p negotiation",
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}
	keys := readTunnelJoinKeys(req)
	subdomainHints, hintSourceCounts := readTunnelJoinSubdomainHints(req)
	m.recordTunnelJoinSubdomainHintSources(hintSourceCounts)
	results := make([]*fbMsg.TunnelChannelStartResultT, 0, len(keys))
	var firstErrorMessage string
	var firstErrorCode uint32

	appendFailureResult := func(key, channelID string, code fbMsg.ErrorCode, message string) {
		res := &fbMsg.TunnelChannelStartResultT{
			Key:                  strings.TrimSpace(key),
			ChannelId:            strings.TrimSpace(channelID),
			Success:              false,
			ErrorCode:            uint32(code),
			ErrorMessage:         strings.TrimSpace(message),
			NegotiatedBufferSize: 0,
		}
		if firstErrorMessage == "" {
			firstErrorMessage = res.ErrorMessage
			firstErrorCode = res.ErrorCode
		}
		results = append(results, res)
	}

	if channelTotal > 0 && len(keys) == 0 {
		appendFailureResult("channel-1", "", fbMsg.ErrorCodeINVALID_MESSAGE, "missing channel key")
	}

	for _, key := range keys {
		resolvedChannelID, target, ok := findPublisherTunnelChannelByKey(tunnelID, key, tunnelTargets)
		if !ok || target == nil {
			appendFailureResult(key, composeTunnelChannelID(tunnelID, key), fbMsg.ErrorCodeCHANNEL_NOT_FOUND, "channel not found")
			if allOrNothing {
				break
			}
			continue
		}
		if strings.TrimSpace(target.LinkType) != "p2p" {
			appendFailureResult(key, resolvedChannelID, fbMsg.ErrorCodeINVALID_MESSAGE, "channel does not enable p2p negotiation")
			if allOrNothing {
				break
			}
			continue
		}
		hintedSubdomain, targetSubdomain, subdomainMismatch := resolveTunnelJoinSubdomainMismatch(
			subdomainHints,
			key,
			target.Subdomain,
		)
		if subdomainMismatch {
			m.recordTunnelJoinSubdomainMismatch()
			logger.Warnf("tunnel join subdomain hint mismatch: tunnel=%s key=%s requested=%s target=%s",
				tunnelID, key, hintedSubdomain, targetSubdomain)
			appendFailureResult(key, resolvedChannelID, fbMsg.ErrorCodeINVALID_MESSAGE, "channel subdomain mismatch")
			if allOrNothing {
				break
			}
			continue
		}

		results = append(results, &fbMsg.TunnelChannelStartResultT{
			Key:                  key,
			ChannelId:            resolvedChannelID,
			Success:              true,
			RemoteEndpoint:       strings.TrimSpace(target.RemoteEndpoint),
			AliasDomain:          strings.TrimSpace(target.AliasDomain),
			CustomDomain:         "",
			AssignedDomain:       strings.TrimSpace(target.Domain),
			ErrorMessage:         "",
			NegotiatedBufferSize: 0,
		})
	}

	summary := summarizeTunnelStartResults(results)
	success := resolveTunnelOperationSuccess(mode, summary)
	if !success && firstErrorCode == 0 {
		firstErrorCode = uint32(fbMsg.ErrorCodeINTERNAL_ERROR)
	}

	resp := &fbMsg.TunnelJoinResponseT{
		Success:         success,
		Mode:            mode,
		TunnelId:        tunnelID,
		EdgeId:          edgeID,
		Summary:         summary,
		Channels:        results,
		RuntimeSnapshot: m.buildTunnelRuntimeSnapshot(tunnelID),
		ErrorCode:       firstErrorCode,
		ErrorMessage:    firstErrorMessage,
	}
	if success {
		if err := m.StartICEForConsumer(tunnelID, ctx.UserID, ctx.DeviceID); err != nil {
			resp.Success = false
			resp.ErrorCode = uint32(fbMsg.ErrorCodeINTERNAL_ERROR)
			resp.ErrorMessage = fmt.Sprintf("start p2p negotiation failed: %v", err)
		} else {
			resp.ErrorCode = 0
			resp.ErrorMessage = ""
		}
	}

	return ctx.Protocol.SendTunnelJoinResponse(ctx.Conn, resp, ctx.SessionID)
}

func (m *ChannelManager) HandleTunnelLeave(ctx *HandlerContext, msg *fbMsg.Message) error {
	req, err := safeParseTunnelLeaveRequest(msg)
	if err != nil {
		logger.Errorf("failed to parse tunnel leave request: %v", err)
		return ctx.Protocol.SendTunnelLeaveResponse(ctx.Conn, &fbMsg.TunnelLeaveResponseT{
			Success:      false,
			Mode:         fbMsg.TunnelStartModeALL_OR_NOTHING,
			ErrorCode:    uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			ErrorMessage: fmt.Sprintf("invalid message format: %v", err),
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	tunnelID := strings.TrimSpace(string(req.TunnelId()))
	edgeID := strings.TrimSpace(string(req.EdgeId()))
	mode := normalizeTunnelStartMode(req.Mode())
	actorRole, _, _, actorCode, actorMessage := resolveTunnelActorContext(req.Actor(nil))
	if actorCode != 0 {
		return ctx.Protocol.SendTunnelLeaveResponse(ctx.Conn, &fbMsg.TunnelLeaveResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(actorCode),
			ErrorMessage: actorMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	if actorRole == fbMsg.TunnelActorRolePUBLISHER {
		return ctx.Protocol.SendTunnelLeaveResponse(ctx.Conn, &fbMsg.TunnelLeaveResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(fbMsg.ErrorCodeAUTH_FAILED),
			ErrorMessage: "leave requires consumer/controller actor role",
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	if tunnelID == "" {
		return ctx.Protocol.SendTunnelLeaveResponse(ctx.Conn, &fbMsg.TunnelLeaveResponseT{
			Success:      false,
			Mode:         mode,
			EdgeId:       edgeID,
			ErrorCode:    uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			ErrorMessage: "missing tunnel_id",
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}
	verifiedEdgeID, verifyCode, verifyMessage := m.verifyTunnelRuntimeOwnership(ctx.UserID, edgeID, tunnelID)
	if verifyCode != 0 {
		return ctx.Protocol.SendTunnelLeaveResponse(ctx.Conn, &fbMsg.TunnelLeaveResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(verifyCode),
			ErrorMessage: verifyMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}
	edgeID = verifiedEdgeID
	if rejectCode, rejectMessage := m.validateTunnelActorContext(
		ctx.UserID,
		edgeID,
		tunnelID,
		actorRole,
		ctx.DeviceID,
	); rejectCode != 0 {
		return ctx.Protocol.SendTunnelLeaveResponse(ctx.Conn, &fbMsg.TunnelLeaveResponseT{
			Success:      false,
			Mode:         mode,
			TunnelId:     tunnelID,
			EdgeId:       edgeID,
			ErrorCode:    uint32(rejectCode),
			ErrorMessage: rejectMessage,
			Summary:      &fbMsg.TunnelOperationSummaryT{},
		}, ctx.SessionID)
	}

	tunnelTargets := m.listTunnelTargets(tunnelID)
	results := make([]*fbMsg.TunnelChannelStopResultT, 0)
	keys := readTunnelLeaveKeys(req)
	var firstErrorMessage string
	var firstErrorCode uint32

	appendFailureResult := func(key, channelID string, code fbMsg.ErrorCode, message string) {
		res := &fbMsg.TunnelChannelStopResultT{
			Key:          strings.TrimSpace(key),
			ChannelId:    strings.TrimSpace(channelID),
			Success:      false,
			ErrorCode:    uint32(code),
			ErrorMessage: strings.TrimSpace(message),
		}
		if firstErrorMessage == "" {
			firstErrorMessage = res.ErrorMessage
			firstErrorCode = res.ErrorCode
		}
		results = append(results, res)
	}

	seen := make(map[string]struct{})
	for _, key := range keys {
		if strings.TrimSpace(key) == "" {
			continue
		}
		channelID, _, ok := findPublisherTunnelChannelByKey(tunnelID, key, tunnelTargets)
		if !ok {
			appendFailureResult(key, composeTunnelChannelID(tunnelID, key), fbMsg.ErrorCodeCHANNEL_NOT_FOUND, "channel not found")
			continue
		}
		if _, exists := seen[channelID]; exists {
			continue
		}
		seen[channelID] = struct{}{}
		results = append(results, &fbMsg.TunnelChannelStopResultT{
			Key:       key,
			ChannelId: channelID,
			Success:   true,
		})
	}

	summary := summarizeTunnelStopResults(results)
	success := resolveTunnelOperationSuccess(mode, summary)

	resp := &fbMsg.TunnelLeaveResponseT{
		Success:         success,
		Mode:            mode,
		TunnelId:        tunnelID,
		EdgeId:          edgeID,
		Summary:         summary,
		Channels:        results,
		RuntimeSnapshot: m.buildTunnelRuntimeSnapshot(tunnelID),
		ErrorCode:       firstErrorCode,
		ErrorMessage:    firstErrorMessage,
	}
	if success {
		reason := strings.TrimSpace(string(req.Reason()))
		m.StopICEForConsumer(tunnelID, ctx.UserID, ctx.DeviceID, reason)
		resp.ErrorCode = 0
		resp.ErrorMessage = ""
	}

	return ctx.Protocol.SendTunnelLeaveResponse(ctx.Conn, resp, ctx.SessionID)
}

func safeParseTunnelStartRequest(msg *fbMsg.Message) (*fbMsg.TunnelStartRequest, error) {
	var req *fbMsg.TunnelStartRequest
	var parseErr error
	defer func() {
		if r := recover(); r != nil {
			req = nil
			parseErr = fmt.Errorf("panic during tunnel start request parsing: %v", r)
		}
	}()

	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return nil, fmt.Errorf("message has no body")
	}
	if table.Bytes == nil || len(table.Bytes) == 0 {
		return nil, fmt.Errorf("message body is empty")
	}
	if table.Pos >= flatbuffers.UOffsetT(len(table.Bytes)) {
		return nil, fmt.Errorf("message body position out of bounds: pos=%d len=%d", table.Pos, len(table.Bytes))
	}

	req = new(fbMsg.TunnelStartRequest)
	req.Init(table.Bytes, table.Pos)

	_ = req.TunnelId()
	_ = req.EdgeId()
	_ = req.Mode()
	_ = req.Reconnect()
	_ = req.ChannelsLength()

	return req, parseErr
}

func safeParseTunnelStopRequest(msg *fbMsg.Message) (*fbMsg.TunnelStopRequest, error) {
	var req *fbMsg.TunnelStopRequest
	var parseErr error
	defer func() {
		if r := recover(); r != nil {
			req = nil
			parseErr = fmt.Errorf("panic during tunnel stop request parsing: %v", r)
		}
	}()

	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return nil, fmt.Errorf("message has no body")
	}
	if table.Bytes == nil || len(table.Bytes) == 0 {
		return nil, fmt.Errorf("message body is empty")
	}
	if table.Pos >= flatbuffers.UOffsetT(len(table.Bytes)) {
		return nil, fmt.Errorf("message body position out of bounds: pos=%d len=%d", table.Pos, len(table.Bytes))
	}

	req = new(fbMsg.TunnelStopRequest)
	req.Init(table.Bytes, table.Pos)

	_ = req.TunnelId()
	_ = req.EdgeId()
	_ = req.Mode()
	_ = req.KeysLength()
	_ = req.Reason()

	return req, parseErr
}

func safeParseTunnelJoinRequest(msg *fbMsg.Message) (*fbMsg.TunnelJoinRequest, error) {
	var req *fbMsg.TunnelJoinRequest
	var parseErr error
	defer func() {
		if r := recover(); r != nil {
			req = nil
			parseErr = fmt.Errorf("panic during tunnel join request parsing: %v", r)
		}
	}()

	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return nil, fmt.Errorf("message has no body")
	}
	if table.Bytes == nil || len(table.Bytes) == 0 {
		return nil, fmt.Errorf("message body is empty")
	}
	if table.Pos >= flatbuffers.UOffsetT(len(table.Bytes)) {
		return nil, fmt.Errorf("message body position out of bounds: pos=%d len=%d", table.Pos, len(table.Bytes))
	}

	req = new(fbMsg.TunnelJoinRequest)
	req.Init(table.Bytes, table.Pos)

	_ = req.TunnelId()
	_ = req.EdgeId()
	_ = req.Mode()
	_ = req.Reconnect()
	_ = req.ChannelsLength()

	return req, parseErr
}

func safeParseTunnelLeaveRequest(msg *fbMsg.Message) (*fbMsg.TunnelLeaveRequest, error) {
	var req *fbMsg.TunnelLeaveRequest
	var parseErr error
	defer func() {
		if r := recover(); r != nil {
			req = nil
			parseErr = fmt.Errorf("panic during tunnel leave request parsing: %v", r)
		}
	}()

	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return nil, fmt.Errorf("message has no body")
	}
	if table.Bytes == nil || len(table.Bytes) == 0 {
		return nil, fmt.Errorf("message body is empty")
	}
	if table.Pos >= flatbuffers.UOffsetT(len(table.Bytes)) {
		return nil, fmt.Errorf("message body position out of bounds: pos=%d len=%d", table.Pos, len(table.Bytes))
	}

	req = new(fbMsg.TunnelLeaveRequest)
	req.Init(table.Bytes, table.Pos)

	_ = req.TunnelId()
	_ = req.EdgeId()
	_ = req.Mode()
	_ = req.KeysLength()
	_ = req.Reason()

	return req, parseErr
}

func normalizeTunnelStartMode(mode fbMsg.TunnelStartMode) fbMsg.TunnelStartMode {
	if mode == fbMsg.TunnelStartModeBEST_EFFORT {
		return fbMsg.TunnelStartModeBEST_EFFORT
	}
	return fbMsg.TunnelStartModeALL_OR_NOTHING
}

func resolveTunnelActorContext(actor *fbMsg.TunnelActorContext) (fbMsg.TunnelActorRole, string, string, fbMsg.ErrorCode, string) {
	if actor == nil {
		return fbMsg.TunnelActorRoleUNKNOWN, "", "", fbMsg.ErrorCodeINVALID_MESSAGE, "missing actor context"
	}

	role := normalizeActorRole(uint8(actor.Role()))
	switch role {
	case fbMsg.TunnelActorRolePUBLISHER, fbMsg.TunnelActorRoleCONSUMER, fbMsg.TunnelActorRoleCONTROLLER:
	default:
		return fbMsg.TunnelActorRoleUNKNOWN, "", "", fbMsg.ErrorCodeINVALID_MESSAGE, "invalid actor role"
	}

	sessionID := strings.TrimSpace(string(actor.SessionId()))
	if sessionID == "" {
		return fbMsg.TunnelActorRoleUNKNOWN, "", "", fbMsg.ErrorCodeINVALID_MESSAGE, "missing actor session_id"
	}
	deviceID := strings.TrimSpace(string(actor.DeviceId()))
	if deviceID == "" {
		return fbMsg.TunnelActorRoleUNKNOWN, "", "", fbMsg.ErrorCodeINVALID_MESSAGE, "missing actor device_id"
	}

	return role, sessionID, deviceID, 0, ""
}

func buildLocalAddr(localHost string, localPort uint16) string {
	host := strings.TrimSpace(localHost)
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s:%d", host, localPort)
}

func composeTunnelChannelID(tunnelID, key string) string {
	id := strings.TrimSpace(tunnelID)
	channelKey := strings.TrimSpace(key)
	if id == "" {
		return channelKey
	}
	if channelKey == "" {
		return id
	}
	return id + ":" + channelKey
}

func inferChannelTypeFromProtocolStrict(protocol string) (fbMsg.ChannelType, bool) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "http":
		return fbMsg.ChannelTypeHTTP, true
	case "https":
		return fbMsg.ChannelTypeHTTPS, true
	case "tcp":
		return fbMsg.ChannelTypeTCP, true
	case "udp":
		return fbMsg.ChannelTypeUDP, true
	case "wireguard", "wg":
		return fbMsg.ChannelTypeWIREGUARD, true
	default:
		return fbMsg.ChannelTypeUNKNOWN, false
	}
}

func isProtocolAllowedByCapabilities(protocol string, caps []string) bool {
	capabilitySet := normalizeCapabilitySet(caps)
	if len(capabilitySet) == 0 {
		// Backward compatibility: old clients may not send capabilities.
		return true
	}

	switch normalizeProtocolName(protocol) {
	case "http", "https":
		_, hasHTTP := capabilitySet["http"]
		_, hasHTTPS := capabilitySet["https"]
		return hasHTTP || hasHTTPS
	case "tcp":
		_, ok := capabilitySet["tcp"]
		return ok
	case "udp":
		_, ok := capabilitySet["udp"]
		return ok
	case "wireguard", "wg":
		_, hasWireGuard := capabilitySet["wireguard"]
		_, hasWG := capabilitySet["wg"]
		return hasWireGuard || hasWG
	default:
		return true
	}
}

func requiredCapabilitiesForProtocol(protocol string) []string {
	switch normalizeProtocolName(protocol) {
	case "http", "https":
		return []string{"http", "https"}
	case "tcp":
		return []string{"tcp"}
	case "udp":
		return []string{"udp"}
	case "wireguard", "wg":
		return []string{"wireguard", "wg"}
	default:
		return nil
	}
}

func capabilityViolationMessage(protocol string) string {
	normalized := normalizeProtocolName(protocol)
	required := requiredCapabilitiesForProtocol(normalized)
	if len(required) == 0 {
		return fmt.Sprintf("capability mismatch: protocol=%s", normalized)
	}
	return fmt.Sprintf("capability mismatch: protocol=%s requires one of [%s]", normalized, strings.Join(required, ","))
}

func normalizeProtocolName(protocol string) string {
	return strings.ToLower(strings.TrimSpace(protocol))
}

func normalizeCapabilitySet(caps []string) map[string]struct{} {
	if len(caps) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(caps))
	for _, cap := range caps {
		name := strings.ToLower(strings.TrimSpace(cap))
		if name == "" {
			continue
		}
		set[name] = struct{}{}
	}
	return set
}

func tunnelLinkTypeFromString(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "p2p":
		return "p2p", true
	case "wireguard", "wg":
		return "wireguard", true
	case "relay":
		return "relay", true
	default:
		return "", false
	}
}

func normalizeTunnelLinkType(raw string) string {
	if linkType, ok := tunnelLinkTypeFromString(raw); ok {
		return linkType
	}
	return "relay"
}

func resolveTunnelLinkPolicy(rawTransport, metadataJSON string) tunnelLinkPolicy {
	policy := defaultTunnelLinkPolicy(normalizeTunnelLinkType(rawTransport))
	override := parseTunnelLinkPolicyOverride(metadataJSON)
	if override != nil {
		if linkType, ok := tunnelLinkTypeFromString(override.LinkType); ok {
			policy.LinkType = linkType
		}
		preferred := override.Preferred
		if len(preferred) == 0 {
			preferred = override.PreferredLinks
		}
		if len(preferred) > 0 {
			policy.PreferredLinks = sanitizeTunnelLinkTypeList(preferred)
		}
		if override.AllowRelayFallback != nil {
			policy.AllowRelayFallback = *override.AllowRelayFallback
		}
		if override.RequireDirect != nil {
			policy.RequireDirect = *override.RequireDirect
		}
	}
	normalizeResolvedTunnelLinkPolicy(&policy)
	return policy
}

func defaultTunnelLinkPolicy(linkType string) tunnelLinkPolicy {
	switch linkType {
	case "p2p":
		return tunnelLinkPolicy{
			LinkType:           "p2p",
			PreferredLinks:     []string{"p2p", "relay"},
			AllowRelayFallback: true,
			RequireDirect:      false,
		}
	case "wireguard":
		return tunnelLinkPolicy{
			LinkType:           "wireguard",
			PreferredLinks:     []string{"wireguard", "relay"},
			AllowRelayFallback: true,
			RequireDirect:      false,
		}
	default:
		return tunnelLinkPolicy{
			LinkType:           "relay",
			PreferredLinks:     []string{"relay"},
			AllowRelayFallback: false,
			RequireDirect:      false,
		}
	}
}

func parseTunnelLinkPolicyOverride(metadataJSON string) *tunnelLinkPolicyOverride {
	raw := strings.TrimSpace(metadataJSON)
	if raw == "" {
		return nil
	}

	env := tunnelMetadataLinkPolicyEnvelope{}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return nil
	}

	if env.LinkPolicy != nil {
		return env.LinkPolicy
	}

	if env.LinkType == "" &&
		len(env.Preferred) == 0 &&
		len(env.PreferredLinks) == 0 &&
		env.AllowRelayFallback == nil &&
		env.RequireDirect == nil {
		return nil
	}

	return &tunnelLinkPolicyOverride{
		LinkType:           env.LinkType,
		Preferred:          env.Preferred,
		PreferredLinks:     env.PreferredLinks,
		AllowRelayFallback: env.AllowRelayFallback,
		RequireDirect:      env.RequireDirect,
	}
}

func parseTunnelSubdomainFromMetadata(metadataJSON string) string {
	raw := strings.TrimSpace(metadataJSON)
	if raw == "" {
		return ""
	}
	var env tunnelMetadataSubdomainEnvelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(env.Subdomain))
}

func resolveTunnelStartSubdomain(spec *fbMsg.TunnelChannelStartSpec) string {
	value, _ := resolveTunnelStartSubdomainWithSource(spec)
	return value
}

func resolveTunnelStartSubdomainWithSource(spec *fbMsg.TunnelChannelStartSpec) (string, tunnelSubdomainResolveSource) {
	if spec == nil {
		return "", tunnelSubdomainResolveSourceNone
	}
	if value := strings.ToLower(strings.TrimSpace(string(spec.Subdomain()))); value != "" {
		return value, tunnelSubdomainResolveSourceField
	}
	value := parseTunnelSubdomainFromMetadata(string(spec.MetadataJson()))
	if value != "" {
		return value, tunnelSubdomainResolveSourceMetadata
	}
	return "", tunnelSubdomainResolveSourceNone
}

func sanitizeTunnelLinkTypeList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		linkType, ok := tunnelLinkTypeFromString(raw)
		if !ok {
			continue
		}
		if _, exists := seen[linkType]; exists {
			continue
		}
		seen[linkType] = struct{}{}
		out = append(out, linkType)
	}
	return out
}

func normalizeResolvedTunnelLinkPolicy(policy *tunnelLinkPolicy) {
	if policy == nil {
		return
	}

	if linkType, ok := tunnelLinkTypeFromString(policy.LinkType); ok {
		policy.LinkType = linkType
	} else {
		policy.LinkType = "relay"
	}

	policy.PreferredLinks = sanitizeTunnelLinkTypeList(policy.PreferredLinks)
	if len(policy.PreferredLinks) == 0 {
		policy.PreferredLinks = []string{policy.LinkType}
	}

	primary := policy.PreferredLinks[0]
	policy.LinkType = primary

	if policy.RequireDirect {
		policy.AllowRelayFallback = false
		withoutRelay := make([]string, 0, len(policy.PreferredLinks))
		for _, item := range policy.PreferredLinks {
			if item == "relay" {
				continue
			}
			withoutRelay = append(withoutRelay, item)
		}
		policy.PreferredLinks = withoutRelay
		if len(policy.PreferredLinks) == 0 {
			policy.PreferredLinks = []string{"p2p"}
		}
		policy.LinkType = policy.PreferredLinks[0]
		return
	}

	if policy.LinkType == "relay" {
		policy.AllowRelayFallback = false
		policy.PreferredLinks = []string{"relay"}
		return
	}

	if !policy.AllowRelayFallback {
		withoutRelay := make([]string, 0, len(policy.PreferredLinks))
		for _, item := range policy.PreferredLinks {
			if item == "relay" {
				continue
			}
			withoutRelay = append(withoutRelay, item)
		}
		if len(withoutRelay) == 0 {
			withoutRelay = []string{policy.LinkType}
		}
		policy.PreferredLinks = withoutRelay
		return
	}

	hasRelay := false
	for _, item := range policy.PreferredLinks {
		if item == "relay" {
			hasRelay = true
			break
		}
	}
	if !hasRelay {
		policy.PreferredLinks = append(policy.PreferredLinks, "relay")
	}
}

func summarizeTunnelStartResults(results []*fbMsg.TunnelChannelStartResultT) *fbMsg.TunnelOperationSummaryT {
	summary := &fbMsg.TunnelOperationSummaryT{
		Requested: uint32(len(results)),
	}
	for _, item := range results {
		if item != nil && item.Success {
			summary.Succeeded++
		}
	}
	summary.Failed = summary.Requested - summary.Succeeded
	return summary
}

func summarizeTunnelStopResults(results []*fbMsg.TunnelChannelStopResultT) *fbMsg.TunnelOperationSummaryT {
	summary := &fbMsg.TunnelOperationSummaryT{
		Requested: uint32(len(results)),
	}
	for _, item := range results {
		if item != nil && item.Success {
			summary.Succeeded++
		}
	}
	summary.Failed = summary.Requested - summary.Succeeded
	return summary
}

func resolveTunnelOperationSuccess(mode fbMsg.TunnelStartMode, summary *fbMsg.TunnelOperationSummaryT) bool {
	if summary == nil {
		return false
	}
	if mode == fbMsg.TunnelStartModeALL_OR_NOTHING {
		return summary.Failed == 0
	}
	return summary.Requested == 0 || summary.Succeeded > 0
}

func buildTunnelStartConfigRaw(
	spec fbMsg.TunnelChannelStartSpec,
	role fbMsg.TunnelActorRole,
	actorSessionID, actorDeviceID string,
	linkPolicy tunnelLinkPolicy,
) []byte {
	raw, err := json.Marshal(tunnelStartConfig{
		RemotePort:         spec.RemotePort(),
		EagerConnectRemote: spec.EagerConnectRemote(),
		ActorRole:          uint8(role),
		ActorSessionID:     strings.TrimSpace(actorSessionID),
		ActorDeviceID:      strings.TrimSpace(actorDeviceID),
		LinkType:           linkPolicy.LinkType,
		PreferredLinks:     sanitizeTunnelLinkTypeList(linkPolicy.PreferredLinks),
		AllowRelayFallback: linkPolicy.AllowRelayFallback,
		RequireDirect:      linkPolicy.RequireDirect,
	})
	if err != nil {
		return nil
	}
	return raw
}

func (m *ChannelManager) buildTunnelRuntimeSnapshot(tunnelID string) *fbMsg.TunnelRuntimeSnapshotT {
	targets := m.listTunnelTargets(tunnelID)
	channelIDs := make([]string, 0, len(targets))
	channelKeys := make([]string, 0, len(targets))
	channels := make([]tunnelRuntimeChannelView, 0, len(targets))
	for channelID, target := range targets {
		channelIDs = append(channelIDs, channelID)
		channelKeys = append(channelKeys, resolveTunnelChannelKey(tunnelID, channelID, target))
		channels = append(channels, tunnelRuntimeChannelView{
			ID:                 channelID,
			Key:                resolveTunnelChannelKey(tunnelID, channelID, target),
			Protocol:           strings.TrimSpace(target.Protocol),
			LinkType:           strings.TrimSpace(target.LinkType),
			PreferredLinks:     cloneStringSlice(target.PreferredLinks),
			AllowRelayFallback: target.AllowRelayFallback,
			RequireDirect:      target.RequireDirect,
			Type:               target.Type.String(),
			LocalAddr:          strings.TrimSpace(target.LocalAddr),
			RemoteEndpoint:     strings.TrimSpace(target.RemoteEndpoint),
			AssignedDomain:     strings.TrimSpace(target.Domain),
			AliasDomain:        strings.TrimSpace(target.AliasDomain),
			State:              target.GetState().String(),
			SessionID:          strings.TrimSpace(target.SessionID),
			UserID:             strings.TrimSpace(target.UserID),
			DeviceID:           strings.TrimSpace(target.DeviceID),
			Hostname:           strings.TrimSpace(target.Hostname),
			ActorRole:          target.ActorRole.String(),
			ActorSessionID:     strings.TrimSpace(target.ActorSessionID),
			ActorDeviceID:      strings.TrimSpace(target.ActorDeviceID),
			ActorHostname:      strings.TrimSpace(target.ActorHostname),
			Port:               target.Port,
		})
	}
	sort.Strings(channelIDs)
	sort.Strings(channelKeys)
	sort.Slice(channels, func(i, j int) bool {
		return channels[i].ID < channels[j].ID
	})

	state := "stopped"
	for _, channel := range channels {
		if channel.State == StateActive.String() {
			state = "active"
			break
		}
	}
	if len(channels) > 0 && state != "active" {
		state = "inactive"
	}

	payload := tunnelRuntimeSnapshotView{
		TunnelID:    tunnelID,
		ChannelIDs:  channelIDs,
		ChannelKeys: channelKeys,
		Channels:    channels,
		Peers:       m.collectTunnelRuntimePeers(tunnelID),
	}
	runtimeJSON, err := json.Marshal(payload)
	if err != nil {
		logger.Warnf("marshal tunnel runtime snapshot failed, tunnel=%s, err=%v", tunnelID, err)
		runtimeJSON = []byte("{}")
	}

	return &fbMsg.TunnelRuntimeSnapshotT{
		TunnelId:    tunnelID,
		State:       state,
		RuntimeJson: string(runtimeJSON),
		UpdatedAt:   uint64(time.Now().UnixMilli()),
	}
}

func (m *ChannelManager) collectTunnelRuntimePeers(tunnelID string) []tunnelRuntimePeerView {
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" || m == nil {
		return nil
	}

	m.mu.RLock()
	runtime := m.p2pRuntime
	m.mu.RUnlock()
	if runtime == nil {
		return nil
	}

	sessions := runtime.SnapshotNamespaceSessions(p2p.NamespaceQUIC)
	if len(sessions) == 0 {
		return nil
	}

	peers := make([]tunnelRuntimePeerView, 0, len(sessions))
	for sessionID, session := range sessions {
		if session == nil {
			continue
		}
		if strings.TrimSpace(session.NetworkID) != tunnelID {
			continue
		}
		peers = append(peers, tunnelRuntimePeerView{
			ID:                 strings.TrimSpace(sessionID),
			NetworkID:          strings.TrimSpace(session.NetworkID),
			InitiatorID:        strings.TrimSpace(session.InitiatorID),
			PeerA:              strings.TrimSpace(session.PeerA),
			PeerB:              strings.TrimSpace(session.PeerB),
			Status:             p2pStatusToString(session.Status),
			PathState:          p2pPathStateToString(session),
			PathType:           p2pPathTypeToString(session.PathType),
			LinkType:           p2pPathTypeToLinkType(session.PathType),
			PreferredLinks:     cloneStringSlice(session.PreferredLinks),
			AllowRelayFallback: session.AllowRelayFallback,
			RequireDirect:      session.RequireDirect,
			LastError:          strings.TrimSpace(session.LastError),
			CreatedAt:          session.CreatedAt.Unix(),
			UpdatedAt:          session.UpdatedAt.Unix(),
		})
	}

	if len(peers) == 0 {
		return nil
	}
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].ID < peers[j].ID
	})
	return peers
}

func readTunnelStopKeys(req *fbMsg.TunnelStopRequest) []string {
	if req == nil {
		return nil
	}
	if req.KeysLength() == 0 {
		return nil
	}
	keys := make([]string, 0, req.KeysLength())
	seen := make(map[string]struct{}, req.KeysLength())
	for i := 0; i < req.KeysLength(); i++ {
		key := strings.TrimSpace(string(req.Keys(i)))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func readTunnelLeaveKeys(req *fbMsg.TunnelLeaveRequest) []string {
	if req == nil {
		return nil
	}
	if req.KeysLength() == 0 {
		return nil
	}
	keys := make([]string, 0, req.KeysLength())
	seen := make(map[string]struct{}, req.KeysLength())
	for i := 0; i < req.KeysLength(); i++ {
		key := strings.TrimSpace(string(req.Keys(i)))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func readTunnelStartKeys(req *fbMsg.TunnelStartRequest) []string {
	if req == nil || req.ChannelsLength() == 0 {
		return nil
	}
	keys := make([]string, 0, req.ChannelsLength())
	seen := make(map[string]struct{}, req.ChannelsLength())
	for i := 0; i < req.ChannelsLength(); i++ {
		var spec fbMsg.TunnelChannelStartSpec
		if !req.Channels(&spec, i) {
			continue
		}
		key := strings.TrimSpace(string(spec.Key()))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func readTunnelJoinKeys(req *fbMsg.TunnelJoinRequest) []string {
	if req == nil || req.ChannelsLength() == 0 {
		return nil
	}
	keys := make([]string, 0, req.ChannelsLength())
	seen := make(map[string]struct{}, req.ChannelsLength())
	for i := 0; i < req.ChannelsLength(); i++ {
		var spec fbMsg.TunnelChannelStartSpec
		if !req.Channels(&spec, i) {
			continue
		}
		key := strings.TrimSpace(string(spec.Key()))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func readTunnelJoinSubdomainHints(req *fbMsg.TunnelJoinRequest) (map[string]string, tunnelJoinSubdomainHintSourceCounts) {
	sourceCounts := tunnelJoinSubdomainHintSourceCounts{}
	if req == nil || req.ChannelsLength() == 0 {
		return nil, sourceCounts
	}
	hints := make(map[string]string, req.ChannelsLength())
	for i := 0; i < req.ChannelsLength(); i++ {
		var spec fbMsg.TunnelChannelStartSpec
		if !req.Channels(&spec, i) {
			continue
		}
		key := strings.TrimSpace(string(spec.Key()))
		if key == "" {
			continue
		}
		subdomain, source := resolveTunnelStartSubdomainWithSource(&spec)
		switch source {
		case tunnelSubdomainResolveSourceField:
			sourceCounts.field++
		case tunnelSubdomainResolveSourceMetadata:
			sourceCounts.metadata++
		default:
			sourceCounts.none++
		}
		if subdomain == "" {
			continue
		}
		if _, exists := hints[key]; exists {
			continue
		}
		hints[key] = subdomain
	}
	return hints, sourceCounts
}

func resolveTunnelJoinSubdomainMismatch(
	subdomainHints map[string]string,
	channelKey string,
	targetSubdomain string,
) (requested string, target string, mismatch bool) {
	if len(subdomainHints) == 0 {
		return "", "", false
	}
	key := strings.TrimSpace(channelKey)
	if key == "" {
		return "", "", false
	}
	requested = strings.ToLower(strings.TrimSpace(subdomainHints[key]))
	if requested == "" {
		return "", "", false
	}
	target = strings.ToLower(strings.TrimSpace(targetSubdomain))
	if target == "" {
		return requested, "", false
	}
	return requested, target, requested != target
}

func (m *ChannelManager) recordTunnelStartSubdomainResolution(source tunnelSubdomainResolveSource) {
	if m == nil {
		return
	}
	atomic.AddUint64(&m.subdomainStats.startTotal, 1)
	switch source {
	case tunnelSubdomainResolveSourceField:
		atomic.AddUint64(&m.subdomainStats.startField, 1)
	case tunnelSubdomainResolveSourceMetadata:
		atomic.AddUint64(&m.subdomainStats.startMetadataFallback, 1)
	default:
		atomic.AddUint64(&m.subdomainStats.startNone, 1)
	}
	atomic.StoreInt64(&m.subdomainStats.updatedAtUnix, time.Now().Unix())
}

func (m *ChannelManager) recordTunnelJoinSubdomainHintSources(sourceCounts tunnelJoinSubdomainHintSourceCounts) {
	if m == nil {
		return
	}
	total := sourceCounts.field + sourceCounts.metadata + sourceCounts.none
	if total == 0 {
		return
	}
	atomic.AddUint64(&m.subdomainStats.joinHintTotal, total)
	if sourceCounts.field > 0 {
		atomic.AddUint64(&m.subdomainStats.joinHintField, sourceCounts.field)
	}
	if sourceCounts.metadata > 0 {
		atomic.AddUint64(&m.subdomainStats.joinHintMetadataFallback, sourceCounts.metadata)
	}
	if sourceCounts.none > 0 {
		atomic.AddUint64(&m.subdomainStats.joinHintNone, sourceCounts.none)
	}
	atomic.StoreInt64(&m.subdomainStats.updatedAtUnix, time.Now().Unix())
}

func (m *ChannelManager) recordTunnelJoinSubdomainMismatch() {
	if m == nil {
		return
	}
	atomic.AddUint64(&m.subdomainStats.joinHintMismatch, 1)
	atomic.StoreInt64(&m.subdomainStats.updatedAtUnix, time.Now().Unix())
}

func (m *ChannelManager) GetSubdomainResolutionStats() *SubdomainResolutionStats {
	if m == nil {
		return nil
	}
	stats := &SubdomainResolutionStats{
		StartTotal:                    atomic.LoadUint64(&m.subdomainStats.startTotal),
		StartFieldTotal:               atomic.LoadUint64(&m.subdomainStats.startField),
		StartMetadataFallbackTotal:    atomic.LoadUint64(&m.subdomainStats.startMetadataFallback),
		StartNoneTotal:                atomic.LoadUint64(&m.subdomainStats.startNone),
		JoinHintTotal:                 atomic.LoadUint64(&m.subdomainStats.joinHintTotal),
		JoinHintFieldTotal:            atomic.LoadUint64(&m.subdomainStats.joinHintField),
		JoinHintMetadataFallbackTotal: atomic.LoadUint64(&m.subdomainStats.joinHintMetadataFallback),
		JoinHintNoneTotal:             atomic.LoadUint64(&m.subdomainStats.joinHintNone),
		JoinHintMismatchTotal:         atomic.LoadUint64(&m.subdomainStats.joinHintMismatch),
		UpdatedAtUnix:                 atomic.LoadInt64(&m.subdomainStats.updatedAtUnix),
	}
	return stats
}

func (m *ChannelManager) selectTunnelChannelsForStartReconnect(
	tunnelID string,
	keys []string,
	actorRole fbMsg.TunnelActorRole,
	actorSessionID string,
	actorDeviceID string,
) []selectedTunnelChannel {
	tunnelTargets := m.listTunnelTargets(tunnelID)
	selected := make([]selectedTunnelChannel, 0, len(tunnelTargets))

	if len(keys) == 0 {
		for channelID, target := range tunnelTargets {
			if !tunnelTargetMatchesActor(target, actorSessionID, actorDeviceID) {
				continue
			}
			selected = append(selected, selectedTunnelChannel{
				Key:       resolveTunnelChannelKey(tunnelID, channelID, target),
				ChannelID: channelID,
			})
		}
		if len(selected) == 0 && actorRole == fbMsg.TunnelActorRolePUBLISHER {
			for channelID, target := range tunnelTargets {
				selected = append(selected, selectedTunnelChannel{
					Key:       resolveTunnelChannelKey(tunnelID, channelID, target),
					ChannelID: channelID,
				})
			}
		}
		sort.Slice(selected, func(i, j int) bool {
			return selected[i].ChannelID < selected[j].ChannelID
		})
		return selected
	}

	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		channelID, ok := findTunnelChannelIDByKeyForActor(
			tunnelID,
			key,
			tunnelTargets,
			actorSessionID,
			actorDeviceID,
		)
		if !ok {
			continue
		}
		if _, dup := seen[channelID]; dup {
			continue
		}
		seen[channelID] = struct{}{}
		selected = append(selected, selectedTunnelChannel{
			Key:       key,
			ChannelID: channelID,
		})
	}
	sort.Slice(selected, func(i, j int) bool {
		return selected[i].ChannelID < selected[j].ChannelID
	})
	return selected
}

func (m *ChannelManager) listTunnelTargets(tunnelID string) map[string]*Channel {
	result := make(map[string]*Channel)
	if strings.TrimSpace(tunnelID) == "" {
		return result
	}

	m.mu.RLock()
	registry := m.registry
	m.mu.RUnlock()
	if registry == nil {
		return result
	}

	allTargets := registry.GetAllTargets()
	for channelID, target := range allTargets {
		if target == nil {
			continue
		}
		if matchTunnelChannelID(tunnelID, channelID) {
			result[channelID] = target
			continue
		}
		if strings.TrimSpace(target.ChannelKey) != "" && channelID == composeTunnelChannelID(tunnelID, target.ChannelKey) {
			result[channelID] = target
		}
	}
	return result
}

// ListTunnelObservedChannels returns edge-observed runtime path information for
// all channels currently bound to one tunnel.
func (m *ChannelManager) ListTunnelObservedChannels(tunnelID string) []TunnelObservedChannel {
	targets := m.listTunnelTargets(tunnelID)
	if len(targets) == 0 {
		return nil
	}

	out := make([]TunnelObservedChannel, 0, len(targets))
	for channelID, target := range targets {
		if target == nil {
			continue
		}
		out = append(out, TunnelObservedChannel{
			ChannelID:      strings.TrimSpace(channelID),
			ChannelKey:     resolveTunnelChannelKey(tunnelID, channelID, target),
			LinkType:       strings.TrimSpace(target.LinkType),
			RemoteEndpoint: strings.TrimSpace(target.RemoteEndpoint),
			ActorRole:      uint8(target.ActorRole),
			SessionID:      strings.TrimSpace(target.SessionID),
			ActorSessionID: strings.TrimSpace(target.ActorSessionID),
			ActorDeviceID:  strings.TrimSpace(target.ActorDeviceID),
			DeviceID:       strings.TrimSpace(target.DeviceID),
			State:          target.GetState().String(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ChannelID < out[j].ChannelID
	})
	return out
}

func findTunnelChannelIDByKey(tunnelID, key string, targets map[string]*Channel) (string, bool) {
	channelID := composeTunnelChannelID(tunnelID, key)
	if _, ok := targets[channelID]; ok {
		return channelID, true
	}
	prefix := channelID + ":"
	for id, target := range targets {
		if target == nil {
			continue
		}
		if strings.TrimSpace(target.ChannelKey) == key {
			return id, true
		}
		if strings.HasPrefix(id, prefix) {
			return id, true
		}
	}
	return "", false
}

func findPublisherTunnelChannelByKey(tunnelID, key string, targets map[string]*Channel) (string, *Channel, bool) {
	channelID := composeTunnelChannelID(tunnelID, key)
	if target, ok := targets[channelID]; ok && target != nil {
		return channelID, target, true
	}

	prefix := channelID + ":"
	candidateIDs := make([]string, 0, len(targets))
	for id, target := range targets {
		if target == nil {
			continue
		}
		if strings.TrimSpace(target.ChannelKey) == key || strings.HasPrefix(id, prefix) {
			candidateIDs = append(candidateIDs, id)
		}
	}
	if len(candidateIDs) == 0 {
		return "", nil, false
	}

	sort.Strings(candidateIDs)
	for _, id := range candidateIDs {
		target := targets[id]
		if target == nil {
			continue
		}
		if target.ActorRole == fbMsg.TunnelActorRolePUBLISHER {
			return id, target, true
		}
	}

	firstID := candidateIDs[0]
	firstTarget := targets[firstID]
	if firstTarget == nil {
		return "", nil, false
	}
	return firstID, firstTarget, true
}

func findTunnelChannelIDByKeyForActor(
	tunnelID string,
	key string,
	targets map[string]*Channel,
	actorSessionID string,
	actorDeviceID string,
) (string, bool) {
	channelID := composeTunnelChannelID(tunnelID, key)
	if target, ok := targets[channelID]; ok && tunnelTargetMatchesActor(target, actorSessionID, actorDeviceID) {
		return channelID, true
	}

	prefix := channelID + ":"
	candidateIDs := make([]string, 0, len(targets))
	for id, target := range targets {
		if target == nil {
			continue
		}
		if strings.TrimSpace(target.ChannelKey) == key || strings.HasPrefix(id, prefix) {
			candidateIDs = append(candidateIDs, id)
		}
	}
	if len(candidateIDs) == 0 {
		return "", false
	}

	sort.Strings(candidateIDs)
	for _, id := range candidateIDs {
		target := targets[id]
		if tunnelTargetMatchesActor(target, actorSessionID, actorDeviceID) {
			return id, true
		}
	}
	return "", false
}

func tunnelTargetMatchesActor(target *Channel, actorSessionID, actorDeviceID string) bool {
	if target == nil {
		return false
	}
	normalizedActorSessionID := strings.TrimSpace(actorSessionID)
	normalizedActorDeviceID := strings.TrimSpace(actorDeviceID)
	if normalizedActorSessionID == "" && normalizedActorDeviceID == "" {
		return true
	}
	if normalizedActorSessionID != "" && strings.TrimSpace(target.ActorSessionID) == normalizedActorSessionID {
		return true
	}
	if normalizedActorDeviceID != "" && strings.TrimSpace(target.ActorDeviceID) == normalizedActorDeviceID {
		return true
	}
	return false
}

func composeTunnelChannelIDForActor(
	tunnelID string,
	key string,
	actorRole fbMsg.TunnelActorRole,
	actorSessionID string,
	actorDeviceID string,
) string {
	baseID := composeTunnelChannelID(tunnelID, key)
	switch actorRole {
	case fbMsg.TunnelActorRoleCONSUMER, fbMsg.TunnelActorRoleCONTROLLER:
	default:
		return baseID
	}

	roleName := "consumer"
	if actorRole == fbMsg.TunnelActorRoleCONTROLLER {
		roleName = "controller"
	}
	actorIdentity := strings.TrimSpace(actorSessionID)
	if actorIdentity == "" {
		actorIdentity = strings.TrimSpace(actorDeviceID)
	}
	actorIdentity = sanitizeChannelIDToken(actorIdentity)
	if actorIdentity == "" {
		actorIdentity = "anon"
	}
	return fmt.Sprintf("%s:%s:%s", baseID, roleName, actorIdentity)
}

func sanitizeChannelIDToken(value string) string {
	if value == "" {
		return ""
	}
	normalized := make([]rune, 0, len(value))
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			normalized = append(normalized, ch)
			continue
		}
		normalized = append(normalized, '-')
	}
	out := strings.Trim(string(normalized), "-_")
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func resolveTunnelChannelKey(tunnelID, channelID string, target *Channel) string {
	if target != nil {
		if key := strings.TrimSpace(target.ChannelKey); key != "" {
			return key
		}
	}
	trimmedTunnelID := strings.TrimSpace(tunnelID)
	trimmedChannelID := strings.TrimSpace(channelID)
	prefix := trimmedTunnelID + ":"
	if strings.HasPrefix(trimmedChannelID, prefix) {
		suffix := strings.TrimSpace(trimmedChannelID[len(prefix):])
		if suffix == "" {
			return ""
		}
		parts := strings.SplitN(suffix, ":", 2)
		return strings.TrimSpace(parts[0])
	}
	return ""
}

func matchTunnelChannelID(tunnelID, channelID string) bool {
	trimmedTunnelID := strings.TrimSpace(tunnelID)
	trimmedChannelID := strings.TrimSpace(channelID)
	if trimmedTunnelID == "" || trimmedChannelID == "" {
		return false
	}
	return trimmedChannelID == trimmedTunnelID || strings.HasPrefix(trimmedChannelID, trimmedTunnelID+":")
}

// CloseTunnelChannels closes all runtime channels that belong to the tunnel ID,
// including actor-suffixed channel IDs (for example consumer/controller).
func (m *ChannelManager) CloseTunnelChannels(tunnelID string) (int, error) {
	normalizedTunnelID := strings.TrimSpace(tunnelID)
	if normalizedTunnelID == "" {
		return 0, fmt.Errorf("tunnel_id is required")
	}

	targets := m.listTunnelTargets(normalizedTunnelID)
	if len(targets) == 0 {
		return 0, nil
	}

	channelIDs := make([]string, 0, len(targets))
	for channelID := range targets {
		channelIDs = append(channelIDs, strings.TrimSpace(channelID))
	}
	sort.Strings(channelIDs)

	closed := 0
	failures := make([]string, 0)
	for _, channelID := range channelIDs {
		if channelID == "" {
			continue
		}
		if err := m.Close(channelID); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", channelID, err))
			continue
		}
		closed++
	}
	if len(failures) > 0 {
		return closed, fmt.Errorf("close tunnel channels failed: %s", strings.Join(failures, "; "))
	}
	return closed, nil
}

func (m *ChannelManager) upsertTunnelDefinitionBeforeStart(
	ctx *HandlerContext,
	req *fbMsg.TunnelStartRequest,
	tunnelID string,
	requestEdgeID string,
) (string, uint32, string) {
	if ctx == nil || req == nil {
		return "", uint32(fbMsg.ErrorCodeINVALID_MESSAGE), "invalid tunnel start context"
	}

	ownerUserID := strings.TrimSpace(ctx.UserID)
	if ownerUserID == "" {
		return "", uint32(fbMsg.ErrorCodeAUTH_FAILED), "missing authenticated user"
	}

	normalizedTunnelID := strings.TrimSpace(tunnelID)
	if normalizedTunnelID == "" {
		return "", uint32(fbMsg.ErrorCodeINVALID_MESSAGE), "missing tunnel_id"
	}

	edgeID, resolveCode, resolveMessage := m.resolveTunnelOperationEdgeID(requestEdgeID)
	if resolveCode != 0 {
		return edgeID, uint32(resolveCode), resolveMessage
	}

	definition := req.Definition(nil)
	if definition == nil {
		return edgeID, 0, ""
	}

	definitionTunnelID := strings.TrimSpace(string(definition.TunnelId()))
	if definitionTunnelID != "" && definitionTunnelID != normalizedTunnelID {
		return edgeID, uint32(fbMsg.ErrorCodeINVALID_MESSAGE), "definition tunnel_id mismatch"
	}

	definitionEdgeID := strings.TrimSpace(string(definition.EdgeId()))
	if definitionEdgeID != "" && definitionEdgeID != edgeID {
		return edgeID, uint32(fbMsg.ErrorCodeINVALID_MESSAGE), "definition edge_id mismatch"
	}
	actorRole, actorSessionID, actorDeviceID, actorCode, actorMessage := resolveTunnelActorContext(req.Actor(nil))
	if actorCode != 0 {
		return edgeID, uint32(actorCode), actorMessage
	}
	if actorRole != fbMsg.TunnelActorRolePUBLISHER {
		return edgeID, uint32(fbMsg.ErrorCodeAUTH_FAILED), "permission denied: only publisher can upsert definition on start"
	}
	if definitionOwnerUserID := strings.TrimSpace(string(definition.OwnerUserId())); definitionOwnerUserID != "" && definitionOwnerUserID != ownerUserID {
		return edgeID, uint32(fbMsg.ErrorCodeAUTH_FAILED), "permission denied: definition owner mismatch"
	}
	if rejectCode, rejectMessage := validateTunnelOwnershipByConfig(
		ownerUserID,
		ctx.DeviceID,
		string(definition.ConfigJson()),
		true,
	); rejectCode != 0 {
		return edgeID, uint32(rejectCode), rejectMessage
	}

	m.mu.RLock()
	store := m.tunnelStore
	m.mu.RUnlock()
	if store == nil {
		return edgeID, uint32(fbMsg.ErrorCodeINTERNAL_ERROR), "tunnel store unavailable for definition upsert"
	}

	currentRevision, err := store.CurrentRevisionByOwnerAndEdge(context.Background(), ownerUserID, edgeID)
	if err != nil {
		return edgeID, uint32(fbMsg.ErrorCodeINTERNAL_ERROR), fmt.Sprintf("read current revision failed: %v", err)
	}
	existing, err := store.Get(context.Background(), ownerUserID, edgeID, normalizedTunnelID)
	if err != nil {
		return edgeID, uint32(fbMsg.ErrorCodeINTERNAL_ERROR), fmt.Sprintf("load tunnel definition failed: %v", err)
	}
	if req.DefinitionIfMatchRevision() > 0 && req.DefinitionIfMatchRevision() != currentRevision {
		if !shouldSkipStartDefinitionRevisionGuard(req, existing, ctx.DeviceID) {
			return edgeID, tunnelStartRevisionConflictCode, "revision conflict"
		}
	}

	rec := &TunnelDefinitionRecord{
		EdgeID:         edgeID,
		OwnerUserID:    ownerUserID,
		TunnelID:       normalizedTunnelID,
		Name:           strings.TrimSpace(string(definition.Name())),
		AppID:          strings.TrimSpace(string(definition.AppId())),
		Protocol:       strings.TrimSpace(string(definition.Protocol())),
		IntentJSON:     string(definition.IntentJson()),
		ConfigJSON:     string(definition.ConfigJson()),
		RuntimeJSON:    string(definition.RuntimeJson()),
		State:          strings.TrimSpace(string(definition.State())),
		ActorRole:      uint8(actorRole),
		ActorSessionID: strings.TrimSpace(actorSessionID),
		ActorDeviceID:  strings.TrimSpace(actorDeviceID),
	}
	if err := store.Upsert(context.Background(), rec); err != nil {
		return edgeID, uint32(fbMsg.ErrorCodeINTERNAL_ERROR), fmt.Sprintf("upsert tunnel definition failed: %v", err)
	}
	return edgeID, 0, ""
}

func (m *ChannelManager) resolveTunnelOperationEdgeID(requestEdgeID string) (string, fbMsg.ErrorCode, string) {
	configEdgeID := ""
	m.mu.RLock()
	if m.config != nil {
		configEdgeID = strings.TrimSpace(m.config.EdgeID)
	}
	m.mu.RUnlock()

	edgeID := strings.TrimSpace(requestEdgeID)
	if configEdgeID != "" {
		if edgeID != "" && edgeID != configEdgeID {
			return "", fbMsg.ErrorCodeAUTH_FAILED, "edge mismatch for tunnel operation"
		}
		edgeID = configEdgeID
	}
	if edgeID == "" {
		return "", fbMsg.ErrorCodeINTERNAL_ERROR, "edge identity unavailable for ownership check"
	}
	return edgeID, 0, ""
}

func normalizeTunnelActorRoleForStartDefinition(role fbMsg.TunnelActorRole) fbMsg.TunnelActorRole {
	switch role {
	case fbMsg.TunnelActorRolePUBLISHER, fbMsg.TunnelActorRoleCONSUMER, fbMsg.TunnelActorRoleCONTROLLER:
		return role
	default:
		return fbMsg.TunnelActorRoleUNKNOWN
	}
}

func firstNonEmptyTrim(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (m *ChannelManager) verifyTunnelRuntimeOwnership(userID, requestEdgeID, tunnelID string) (string, fbMsg.ErrorCode, string) {
	ownerUserID := strings.TrimSpace(userID)
	if ownerUserID == "" {
		return "", fbMsg.ErrorCodeAUTH_FAILED, "missing authenticated user"
	}

	normalizedTunnelID := strings.TrimSpace(tunnelID)
	if normalizedTunnelID == "" {
		return "", fbMsg.ErrorCodeINVALID_MESSAGE, "missing tunnel_id"
	}

	edgeID, resolveCode, resolveMessage := m.resolveTunnelOperationEdgeID(requestEdgeID)
	if resolveCode != 0 {
		return edgeID, resolveCode, resolveMessage
	}

	m.mu.RLock()
	store := m.tunnelStore
	m.mu.RUnlock()
	if store == nil {
		return edgeID, fbMsg.ErrorCodeINTERNAL_ERROR, "tunnel store unavailable for ownership verification"
	}

	record, err := store.Get(context.Background(), ownerUserID, edgeID, normalizedTunnelID)
	if err != nil {
		logger.Warnf(
			"tunnel ownership check failed, edge=%s tunnel=%s user=%s err=%v",
			edgeID,
			normalizedTunnelID,
			ownerUserID,
			err,
		)
		return edgeID, fbMsg.ErrorCodeINTERNAL_ERROR, "failed to verify tunnel ownership"
	}
	if record == nil {
		records, listErr := store.ListByEdge(context.Background(), edgeID, true)
		if listErr != nil {
			logger.Warnf(
				"tunnel ownership fallback scan failed, edge=%s tunnel=%s user=%s err=%v",
				edgeID,
				normalizedTunnelID,
				ownerUserID,
				listErr,
			)
		} else {
			var foundByOtherOwner bool
			var foundDeleted bool
			for _, item := range records {
				if item == nil {
					continue
				}
				if strings.TrimSpace(item.TunnelID) != normalizedTunnelID {
					continue
				}
				itemOwner := strings.TrimSpace(item.OwnerUserID)
				if itemOwner != "" && itemOwner != ownerUserID {
					foundByOtherOwner = true
					continue
				}
				if item.DeletedAt != nil {
					foundDeleted = true
				}
			}
			if foundByOtherOwner {
				logger.Warnf(
					"tunnel ownership denied by owner mismatch, edge=%s tunnel=%s user=%s",
					edgeID,
					normalizedTunnelID,
					ownerUserID,
				)
				return edgeID, fbMsg.ErrorCodeAUTH_FAILED, "permission denied: owner mismatch"
			}
			if foundDeleted {
				logger.Warnf(
					"tunnel ownership denied by deleted record, edge=%s tunnel=%s user=%s",
					edgeID,
					normalizedTunnelID,
					ownerUserID,
				)
				return edgeID, fbMsg.ErrorCodeAUTH_FAILED, "tunnel definition is deleted, please refresh and retry"
			}
		}
		logger.Warnf(
			"tunnel ownership denied by missing record, edge=%s tunnel=%s user=%s",
			edgeID,
			normalizedTunnelID,
			ownerUserID,
		)
		return edgeID, fbMsg.ErrorCodeAUTH_FAILED, "tunnel definition not found, please sync and retry"
	}
	if record.DeletedAt != nil {
		logger.Warnf(
			"tunnel ownership denied by deleted record, edge=%s tunnel=%s user=%s",
			edgeID,
			normalizedTunnelID,
			ownerUserID,
		)
		return edgeID, fbMsg.ErrorCodeAUTH_FAILED, "tunnel definition is deleted, please refresh and retry"
	}

	return edgeID, 0, ""
}

func (m *ChannelManager) validateTunnelActorContext(
	userID string,
	edgeID string,
	tunnelID string,
	actorRole fbMsg.TunnelActorRole,
	requestDeviceID string,
) (fbMsg.ErrorCode, string) {
	if actorRole != fbMsg.TunnelActorRoleCONSUMER &&
		actorRole != fbMsg.TunnelActorRolePUBLISHER &&
		actorRole != fbMsg.TunnelActorRoleCONTROLLER {
		return 0, ""
	}

	store := m.GetTunnelStore()
	if store == nil {
		return fbMsg.ErrorCodeINTERNAL_ERROR, "tunnel store unavailable for actor validation"
	}

	record, err := store.Get(
		context.Background(),
		strings.TrimSpace(userID),
		strings.TrimSpace(edgeID),
		strings.TrimSpace(tunnelID),
	)
	if err != nil {
		logger.Warnf(
			"tunnel actor validation failed, edge=%s tunnel=%s user=%s actorRole=%s err=%v",
			strings.TrimSpace(edgeID),
			strings.TrimSpace(tunnelID),
			strings.TrimSpace(userID),
			actorRole.String(),
			err,
		)
		return fbMsg.ErrorCodeINTERNAL_ERROR, "failed to validate tunnel actor context"
	}
	if record == nil {
		return 0, ""
	}

	return validateTunnelOwnershipByConfig(userID, requestDeviceID, record.ConfigJSON, actorRole == fbMsg.TunnelActorRolePUBLISHER)
}

func validateTunnelOwnershipByConfig(
	requestUserID string,
	requestDeviceID string,
	configJSON string,
	requireManagerDevice bool,
) (fbMsg.ErrorCode, string) {
	normalizedUserID := strings.TrimSpace(requestUserID)
	if normalizedUserID == "" {
		return fbMsg.ErrorCodeAUTH_FAILED, "missing authenticated user"
	}
	configOwnerUserID := resolveConfigOwnerUserID(configJSON)
	if configOwnerUserID != "" && configOwnerUserID != normalizedUserID {
		return fbMsg.ErrorCodeAUTH_FAILED, "permission denied: owner mismatch"
	}
	if !requireManagerDevice {
		return 0, ""
	}
	managerDeviceID := resolveConfigManagerDeviceID(configJSON)
	if managerDeviceID == "" {
		return 0, ""
	}
	if strings.TrimSpace(requestDeviceID) != managerDeviceID {
		return fbMsg.ErrorCodeAUTH_FAILED, "permission denied: manager device mismatch"
	}
	return 0, ""
}

func resolveConfigOwnerUserID(configJSON string) string {
	payload, configObj := parseTunnelConfigPayload(configJSON)
	if payload == nil && configObj == nil {
		return ""
	}
	return firstNonEmptyTrim(
		readStringFromConfigPayload(payload, "owner"),
		readStringFromConfigPayload(configObj, "owner"),
	)
}

func resolveConfigManagerDeviceID(configJSON string) string {
	payload, configObj := parseTunnelConfigPayload(configJSON)
	if payload == nil && configObj == nil {
		return ""
	}
	return firstNonEmptyTrim(
		readStringFromConfigPayload(payload, "managerDeviceId"),
		readStringFromConfigPayload(configObj, "managerDeviceId"),
	)
}

func parseTunnelConfigPayload(configJSON string) (map[string]any, map[string]any) {
	raw := strings.TrimSpace(configJSON)
	if raw == "" {
		return nil, nil
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, nil
	}
	configObj, _ := payload["config"].(map[string]any)
	return payload, configObj
}

func readStringFromConfigPayload(obj map[string]any, key string) string {
	if obj == nil {
		return ""
	}
	value, ok := obj[key]
	if !ok {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", value))
}

func shouldSkipStartDefinitionRevisionGuard(
	req *fbMsg.TunnelStartRequest,
	existing *TunnelDefinitionRecord,
	sessionDeviceID string,
) bool {
	if req == nil {
		return false
	}
	sessionDeviceID = strings.TrimSpace(sessionDeviceID)
	if sessionDeviceID == "" {
		return false
	}
	definition := req.Definition(nil)
	if definition == nil {
		return false
	}

	// Consumer/join path keeps optimistic-concurrency protection.
	if normalizeTunnelActorRoleForStartDefinition(definition.ActorRole()) == fbMsg.TunnelActorRoleCONSUMER {
		return false
	}

	nextConfigJSON := strings.TrimSpace(string(definition.ConfigJson()))
	currentConfigJSON := ""
	if existing != nil {
		currentConfigJSON = strings.TrimSpace(existing.ConfigJSON)
	}
	_, isExclusive := tunnelpolicy.ResolveSharedModeFromConfig(nextConfigJSON)
	if !isExclusive {
		return false
	}
	if _, existingExclusive := tunnelpolicy.ResolveSharedModeFromConfig(currentConfigJSON); currentConfigJSON != "" && !existingExclusive {
		return false
	}

	nextManagerDeviceID, nextCreatorDeviceID, _ := tunnelpolicy.ResolveOwnershipFieldsFromConfig(nextConfigJSON)
	currentManagerDeviceID, currentCreatorDeviceID, _ := tunnelpolicy.ResolveOwnershipFieldsFromConfig(currentConfigJSON)
	managerDeviceID := firstNonEmptyTrim(
		firstNonEmptyTrim(nextManagerDeviceID, nextCreatorDeviceID),
		firstNonEmptyTrim(currentManagerDeviceID, currentCreatorDeviceID),
	)
	if managerDeviceID == "" {
		return false
	}
	return managerDeviceID == sessionDeviceID
}
