package channel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	chtype "icool.io/yat/edge/internal/channel/types"
	logger "icool.io/yat/edge/pkg/log"
)

const channelActivityPersistMinInterval = 30 * time.Second

type Registry struct {
	resources *ResourcePool
	runtimes  map[fbMsg.ChannelType]ChannelRuntime

	targets        map[string]*Channel // id -> target
	sessionTargets map[string][]string // sessionID -> []targetID
	domainTargets  map[string]string   // route key(alias/subdomain) -> targetID
	portTargets    map[string]string   // "<channelType>:<port>" -> targetID
	// Same tunnel channel (same session + channelKey + localPort) should preferably
	// reuse the same remote port across TCP/UDP.
	portShareHints     map[string]uint16 // "<sessionID>|<channelKey>|<localPort>" -> remotePort
	targetPortShareKey map[string]string // targetID -> portShareKey
	// lastPersistedActivityAt throttles channel activity persistence to avoid
	// excessive database writes on high-frequency control-plane messages.
	lastPersistedActivityAt map[string]time.Time // channelID -> last persisted activity time

	// Config
	httpPort             uint16
	httpsPort            uint16
	maxTargetsPerSession int
	maxTargets           int

	// Storage
	store *ChannelStore

	mu sync.RWMutex
}

// Config
type RegistryConfig struct {
	ResourceConfig       *ResourceConfig
	DomainProvider       DomainProvider
	HTTPPort             uint16
	HTTPSPort            uint16
	MaxTargetsPerSession int
	MaxTargets           int
}

// Config
func DefaultRegistryConfig() *RegistryConfig {
	return &RegistryConfig{
		ResourceConfig:       DefaultResourceConfig(),
		HTTPPort:             80,
		HTTPSPort:            443,
		MaxTargetsPerSession: 10,
		MaxTargets:           1000,
	}
}

// Create
func NewRegistry(config *RegistryConfig) *Registry {
	if config == nil {
		config = DefaultRegistryConfig()
	}

	resources := NewResourcePool(config.ResourceConfig, config.DomainProvider)

	r := &Registry{
		resources:               resources,
		runtimes:                make(map[fbMsg.ChannelType]ChannelRuntime),
		targets:                 make(map[string]*Channel),
		sessionTargets:          make(map[string][]string),
		domainTargets:           make(map[string]string),
		portTargets:             make(map[string]string),
		portShareHints:          make(map[string]uint16),
		targetPortShareKey:      make(map[string]string),
		lastPersistedActivityAt: make(map[string]time.Time),
		httpPort:                config.HTTPPort,
		httpsPort:               config.HTTPSPort,
		maxTargetsPerSession:    config.MaxTargetsPerSession,
		maxTargets:              config.MaxTargets,
	}
	return r
}

func (r *Registry) SetRuntime(typ fbMsg.ChannelType, runtime ChannelRuntime) {
	r.mu.Lock()
	r.runtimes[typ] = runtime
	r.mu.Unlock()
}

func (r *Registry) ClearRuntimes() {
	r.mu.Lock()
	r.runtimes = make(map[fbMsg.ChannelType]ChannelRuntime)
	r.mu.Unlock()
}

// SetStore 设置 ChannelStore
func (r *Registry) SetStore(store *ChannelStore) {
	r.mu.Lock()
	r.store = store
	r.mu.Unlock()
}

func (r *Registry) HasStore() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.store != nil
}

// Re-export from types/.
type CreateRequest = chtype.CreateRequest
type CreateResult = chtype.CreateResult

// Create
func (r *Registry) Create(req *CreateRequest) (*CreateResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	req.Normalize()

	existingTarget, exists := r.targets[req.ID]

	// 仅在新建或跨 session 迁移时检查限额
	if !exists && len(r.targets) >= r.maxTargets {
		return &CreateResult{
			Success:      false,
			TargetID:     req.ID,
			ErrorCode:    uint32(fbMsg.ErrorCodeTUNNEL_LIMIT_EXCEEDED),
			ErrorMessage: "max targets exceeded",
		}, nil
	}
	if (!exists || existingTarget.SessionID != req.SessionID) &&
		len(r.sessionTargets[req.SessionID]) >= r.maxTargetsPerSession {
		return &CreateResult{
			Success:      false,
			TargetID:     req.ID,
			ErrorCode:    uint32(fbMsg.ErrorCodeTUNNEL_LIMIT_EXCEEDED),
			ErrorMessage: "max targets per session exceeded",
		}, nil
	}

	switch req.Type {
	case fbMsg.ChannelTypeHTTP, fbMsg.ChannelTypeHTTPS:
		return r.createOrUpdateHTTPLocked(req, existingTarget, exists)
	default:
		return r.createNonHTTPWithReplaceLocked(req, existingTarget, exists)
	}
}

func (r *Registry) createNonHTTPWithReplaceLocked(req *CreateRequest, existingTarget *Channel, exists bool) (*CreateResult, error) {
	// 非 HTTP channel，沿用 close+create 语义，避免 target/session 映射重复
	if exists {
		if err := r.closeLocked(existingTarget); err != nil {
			return nil, err
		}
	}
	return r.createNonHTTPChannelLocked(req), nil
}

func (r *Registry) createNonHTTPChannelLocked(req *CreateRequest) *CreateResult {
	target := NewChannel(req.ID, req.Type, req.SessionID, req.UserID, req.DeviceID, req.DeviceHostname, req.LocalAddr)
	r.applyActorContext(target, req)
	target.EagerConnectRemote = req.EagerConnectRemote
	target.ChannelKey = req.ChannelKey
	target.Protocol = req.Protocol
	target.LinkType = req.LinkType
	if len(req.PreferredLinks) > 0 {
		target.PreferredLinks = append([]string(nil), req.PreferredLinks...)
	} else {
		target.PreferredLinks = nil
	}
	target.AllowRelayFallback = req.AllowRelayFallback
	target.RequireDirect = req.RequireDirect
	target.ConnRemoteAddr = req.ConnRemoteAddr
	result := &CreateResult{Success: true, TargetID: req.ID, ChannelKey: req.ChannelKey}

	runtimeBound, failedResult := r.allocateAndBindNonHTTPResourcesLocked(req, target, result)
	if failedResult != nil {
		return failedResult
	}

	if !runtimeBound {
		if err := r.upsertRuntimeLocked(target, nil); err != nil {
			r.releaseResourcesOnBindRuntimeFailureLocked(req.Type, target)
			return &CreateResult{
				Success:      false,
				TargetID:     req.ID,
				ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
				ErrorMessage: fmt.Sprintf("bind runtime failed: %v", err),
			}
		}
	}
	target.SetState(StateActive)

	r.rememberPortShareHintLocked(req, target)
	r.targets[req.ID] = target
	r.attachToSessionLocked(req.SessionID, req.ID)

	logger.Infof("target created: id=%s, type=%v, session=%s, domain=%s, port=%d",
		req.ID, req.Type, req.SessionID, target.Domain, target.Port)

	if err := r.saveCreateRecordLocked(req, target); err != nil {
		logger.Warnf("failed to save channel to db: %v", err)
	}

	return result
}

func (r *Registry) applyActorContext(target *Channel, req *CreateRequest) {
	if target == nil || req == nil {
		return
	}
	target.ActorRole = normalizeActorRole(uint8(req.ActorRole))
	target.Hostname = strings.TrimSpace(req.DeviceHostname)

	actorSessionID := strings.TrimSpace(req.ActorSessionID)
	if actorSessionID == "" {
		actorSessionID = strings.TrimSpace(target.SessionID)
	}
	target.ActorSessionID = actorSessionID

	actorDeviceID := strings.TrimSpace(req.ActorDeviceID)
	if actorDeviceID == "" {
		actorDeviceID = strings.TrimSpace(target.DeviceID)
	}
	target.ActorDeviceID = actorDeviceID

	actorHostname := strings.TrimSpace(req.ActorHostname)
	if actorHostname == "" {
		actorHostname = strings.TrimSpace(target.Hostname)
	}
	target.ActorHostname = actorHostname
}

func (r *Registry) allocateAndBindNonHTTPResourcesLocked(req *CreateRequest, target *Channel, result *CreateResult) (bool, *CreateResult) {
	switch req.Type {
	case fbMsg.ChannelTypeTCP:
		return r.allocateAndBindTCPResourcesLocked(req, target, result)
	case fbMsg.ChannelTypeUDP, fbMsg.ChannelTypeWIREGUARD:
		return false, r.allocateUDPResourcesLocked(req, target, result)
	default:
		return false, nil
	}
}

func (r *Registry) allocateAndBindTCPResourcesLocked(req *CreateRequest, target *Channel, result *CreateResult) (bool, *CreateResult) {
	tcpDomain := r.resolveTCPRemoteDomainLocked()
	target.Domain = tcpDomain
	result.Domain = tcpDomain
	if target.ActorRole != fbMsg.TunnelActorRolePUBLISHER {
		// Consumer/controller channels are logical runtime markers for
		// negotiation/dataplane state. They must not create relay listeners.
		target.Port = 0
		target.RemoteEndpoint = ""
		result.Port = 0
		result.RemoteEndpoint = ""
		return false, nil
	}

	requestedPort := req.RemotePort
	requestedFromShareHint := false
	if requestedPort == 0 {
		if hintedPort, ok := r.resolvePortShareHintLocked(req); ok {
			requestedPort = hintedPort
			requestedFromShareHint = true
		}
	}

	if requestedPort > 0 {
		port, err := r.resources.AllocateTCPPort(requestedPort)
		if err != nil {
			if requestedFromShareHint {
				logger.Debugf("hinted TCP port unavailable, fallback to auto, target=%s, port=%d, err=%v", req.ID, requestedPort, err)
			} else {
				return true, &CreateResult{
					Success:      false,
					TargetID:     req.ID,
					ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
					ErrorMessage: fmt.Sprintf("allocate requested TCP port %d failed: %v", requestedPort, err),
				}
			}
		} else {
			target.Port = port
			result.Port = port
			remoteEndpoint := composeRemoteAddr(tcpDomain, port)
			result.RemoteEndpoint = remoteEndpoint
			target.RemoteEndpoint = remoteEndpoint
			r.portTargets[portTargetMapKey(target.Type, port)] = req.ID

			if err := r.upsertRuntimeLocked(target, nil); err != nil {
				r.resources.ReleaseTCP(port)
				delete(r.portTargets, portTargetMapKey(target.Type, port))

				if requestedFromShareHint {
					logger.Debugf("hinted TCP port bind failed, fallback to auto, target=%s, port=%d, err=%v", req.ID, port, err)
				} else if isAddrAlreadyInUseError(err) {
					return true, &CreateResult{
						Success:      false,
						TargetID:     req.ID,
						ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
						ErrorMessage: fmt.Sprintf("requested TCP port %d is unavailable", port),
					}
				} else {
					return true, &CreateResult{
						Success:      false,
						TargetID:     req.ID,
						ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
						ErrorMessage: fmt.Sprintf("listen TCP failed: %v", err),
					}
				}
			} else {
				return true, nil
			}
		}
	}

	attemptedPorts := make(map[uint16]struct{})
	for {
		port, err := r.resources.AllocateTCP()
		if err != nil {
			return true, &CreateResult{
				Success:      false,
				TargetID:     req.ID,
				ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
				ErrorMessage: fmt.Sprintf("allocate TCP port failed: %v", err),
			}
		}

		// ResourcePool only tracks ports allocated by this process.
		// Detect one full round to avoid retrying forever when all ports conflict with external listeners.
		if _, seen := attemptedPorts[port]; seen {
			r.resources.ReleaseTCP(port)
			return true, &CreateResult{
				Success:      false,
				TargetID:     req.ID,
				ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
				ErrorMessage: "no available TCP ports in configured range",
			}
		}
		attemptedPorts[port] = struct{}{}

		target.Port = port
		result.Port = port
		remoteEndpoint := composeRemoteAddr(tcpDomain, port)
		result.RemoteEndpoint = remoteEndpoint
		target.RemoteEndpoint = remoteEndpoint
		r.portTargets[portTargetMapKey(target.Type, port)] = req.ID

		if err := r.upsertRuntimeLocked(target, nil); err != nil {
			r.resources.ReleaseTCP(port)
			delete(r.portTargets, portTargetMapKey(target.Type, port))

			if isAddrAlreadyInUseError(err) {
				logger.Warnf("tcp port %d is unavailable, retrying with next port for target=%s", port, req.ID)
				continue
			}

			return true, &CreateResult{
				Success:      false,
				TargetID:     req.ID,
				ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
				ErrorMessage: fmt.Sprintf("listen TCP failed: %v", err),
			}
		}

		return true, nil
	}
}

func (r *Registry) allocateUDPResourcesLocked(req *CreateRequest, target *Channel, result *CreateResult) *CreateResult {
	udpDomain := ""
	if req.Type == fbMsg.ChannelTypeUDP {
		udpDomain = r.resolveTCPRemoteDomainLocked()
		target.Domain = udpDomain
		result.Domain = udpDomain
	}
	if target.ActorRole != fbMsg.TunnelActorRolePUBLISHER {
		// Keep consumer/controller UDP channels as logical-only entries to avoid
		// accidental relay port allocation.
		target.Port = 0
		target.RemoteEndpoint = ""
		result.Port = 0
		result.RemoteEndpoint = ""
		return nil
	}

	requestedPort := req.RemotePort
	requestedFromShareHint := false
	if requestedPort == 0 {
		if hintedPort, ok := r.resolvePortShareHintLocked(req); ok {
			requestedPort = hintedPort
			requestedFromShareHint = true
		}
	}

	allocateRequested := func(port uint16) error {
		allocatedPort, err := r.resources.AllocateUDPPort(port)
		if err != nil {
			return err
		}
		target.Port = allocatedPort
		result.Port = allocatedPort
		remoteEndpoint := composeRemoteAddr(udpDomain, allocatedPort)
		result.RemoteEndpoint = remoteEndpoint
		target.RemoteEndpoint = remoteEndpoint
		r.portTargets[portTargetMapKey(target.Type, allocatedPort)] = req.ID
		return nil
	}

	if requestedPort > 0 {
		if err := allocateRequested(requestedPort); err != nil {
			if requestedFromShareHint {
				logger.Debugf("hinted UDP port unavailable, fallback to auto, target=%s, port=%d, err=%v", req.ID, requestedPort, err)
			} else {
				return &CreateResult{
					Success:      false,
					TargetID:     req.ID,
					ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
					ErrorMessage: fmt.Sprintf("allocate requested UDP port %d failed: %v", requestedPort, err),
				}
			}
		} else {
			return nil
		}
	}

	port, err := r.resources.AllocateUDP()
	if err != nil {
		return &CreateResult{
			Success:      false,
			TargetID:     req.ID,
			ErrorCode:    uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			ErrorMessage: fmt.Sprintf("allocate UDP port failed: %v", err),
		}
	}

	target.Port = port
	result.Port = port
	remoteEndpoint := composeRemoteAddr(udpDomain, port)
	result.RemoteEndpoint = remoteEndpoint
	target.RemoteEndpoint = remoteEndpoint
	r.portTargets[portTargetMapKey(target.Type, port)] = req.ID

	return nil
}

func (r *Registry) releaseResourcesOnBindRuntimeFailureLocked(typ fbMsg.ChannelType, target *Channel) {
	if target == nil {
		return
	}
	switch typ {
	case fbMsg.ChannelTypeUDP, fbMsg.ChannelTypeWIREGUARD:
		if target.Port > 0 {
			r.resources.ReleaseUDP(target.Port)
			delete(r.portTargets, portTargetMapKey(target.Type, target.Port))
		}
	}
}

func (r *Registry) saveCreateRecordLocked(req *CreateRequest, target *Channel) error {
	if r.store == nil || req == nil {
		return nil
	}
	port := uint16(0)
	if target != nil {
		port = target.Port
	}
	record := &ChannelRecord{
		ChannelID:    req.ID,
		SessionID:    req.SessionID,
		Type:         req.Type,
		LocalAddr:    req.LocalAddr,
		Port:         port,
		Subdomain:    req.Subdomain,
		AliasDomain:  req.AliasDomain,
		CreatedAt:    time.Now(),
		LastActiveAt: time.Now(),
	}
	return r.store.Save(context.Background(), record)
}

func resolveAllocatedSubdomain(assignedDomain, fallback string) string {
	if subdomain := strings.TrimSpace(extractSubdomain(assignedDomain)); subdomain != "" {
		return strings.ToLower(subdomain)
	}
	return strings.ToLower(strings.TrimSpace(fallback))
}

func subdomainRouteKey(subdomain string) string {
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	if subdomain == "" {
		return ""
	}
	return "sub:" + subdomain
}

func aliasRouteKey(aliasDomain string) string {
	aliasDomain = normalizeDomain(aliasDomain)
	if aliasDomain == "" {
		return ""
	}
	return "alias:" + aliasDomain
}

func portTargetMapKey(channelType fbMsg.ChannelType, port uint16) string {
	return fmt.Sprintf("%d:%d", channelType, port)
}

func parseLocalPortFromAddress(localAddr string) uint16 {
	trimmed := strings.TrimSpace(localAddr)
	if trimmed == "" {
		return 0
	}

	if strings.HasPrefix(trimmed, "[") {
		if _, portText, err := net.SplitHostPort(trimmed); err == nil {
			if parsed, parseErr := strconv.Atoi(portText); parseErr == nil && parsed > 0 && parsed < 65536 {
				return uint16(parsed)
			}
		}
		return 0
	}

	if strings.Count(trimmed, ":") == 1 {
		parts := strings.SplitN(trimmed, ":", 2)
		portText := strings.TrimSpace(parts[1])
		parsed, parseErr := strconv.Atoi(portText)
		if parseErr == nil && parsed > 0 && parsed < 65536 {
			return uint16(parsed)
		}
	}

	if _, portText, err := net.SplitHostPort(trimmed); err == nil {
		if parsed, parseErr := strconv.Atoi(portText); parseErr == nil && parsed > 0 && parsed < 65536 {
			return uint16(parsed)
		}
	}

	return 0
}

func (r *Registry) resolvePortShareKey(req *CreateRequest) string {
	if req == nil {
		return ""
	}
	if req.Type != fbMsg.ChannelTypeTCP && req.Type != fbMsg.ChannelTypeUDP {
		return ""
	}

	sessionID := strings.TrimSpace(req.SessionID)
	channelKey := strings.TrimSpace(req.ChannelKey)
	localPort := parseLocalPortFromAddress(req.LocalAddr)
	if sessionID == "" || channelKey == "" || localPort == 0 {
		return ""
	}
	return fmt.Sprintf("%s|%s|%d", sessionID, strings.ToLower(channelKey), localPort)
}

func (r *Registry) resolvePortShareHintLocked(req *CreateRequest) (uint16, bool) {
	key := r.resolvePortShareKey(req)
	if key != "" {
		port, ok := r.portShareHints[key]
		if ok && port > 0 {
			return port, true
		}
	}

	if req == nil || r.store == nil {
		return 0, false
	}
	rec, err := r.store.Get(context.Background(), req.ID)
	if err != nil {
		logger.Debugf("load channel history failed when resolving port hint, channel=%s, err=%v", req.ID, err)
		return 0, false
	}
	if rec == nil || rec.Port == 0 {
		return 0, false
	}
	if rec.Type != req.Type {
		return 0, false
	}

	tcpMin, tcpMax, udpMin, udpMax := r.resources.GetPortRange()
	switch req.Type {
	case fbMsg.ChannelTypeTCP:
		if rec.Port < tcpMin || rec.Port > tcpMax {
			return 0, false
		}
	case fbMsg.ChannelTypeUDP:
		if rec.Port < udpMin || rec.Port > udpMax {
			return 0, false
		}
	default:
		return 0, false
	}
	if key != "" {
		r.portShareHints[key] = rec.Port
	}
	return rec.Port, true
}

func (r *Registry) rememberPortShareHintLocked(req *CreateRequest, target *Channel) {
	if req == nil || target == nil || target.Port == 0 {
		return
	}
	key := r.resolvePortShareKey(req)
	if key == "" {
		return
	}
	r.portShareHints[key] = target.Port
	r.targetPortShareKey[target.ID] = key
}

func (r *Registry) forgetPortShareHintByTargetLocked(targetID string, lastKnownPort uint16) {
	key := strings.TrimSpace(r.targetPortShareKey[targetID])
	if key == "" {
		return
	}
	delete(r.targetPortShareKey, targetID)

	for id, candidateKey := range r.targetPortShareKey {
		if candidateKey != key {
			continue
		}
		if target, ok := r.targets[id]; ok && target != nil && target.Port > 0 {
			r.portShareHints[key] = target.Port
			return
		}
	}

	if lastKnownPort > 0 {
		r.portShareHints[key] = lastKnownPort
		return
	}
	delete(r.portShareHints, key)
}

func (r *Registry) attachToSessionLocked(sessionID, targetID string) {
	for _, id := range r.sessionTargets[sessionID] {
		if id == targetID {
			return
		}
	}
	r.sessionTargets[sessionID] = append(r.sessionTargets[sessionID], targetID)
}

func (r *Registry) upsertRuntimeLocked(target *Channel, previous *Channel) error {
	if target == nil {
		return nil
	}
	runtime := r.runtimes[target.Type]
	if runtime == nil {
		return nil
	}
	return runtime.Upsert(target, previous)
}

func (r *Registry) removeRuntimeLocked(target *Channel) {
	if target == nil {
		return
	}
	runtime := r.runtimes[target.Type]
	if runtime == nil {
		return
	}
	if err := runtime.Remove(target); err != nil {
		logger.Warnf("remove runtime failed, target=%s, type=%v, err=%v", target.ID, target.Type, err)
	}
}

func composeRemoteAddr(domain string, port uint16) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Sprintf(":%d", port)
	}
	return net.JoinHostPort(domain, strconv.Itoa(int(port)))
}

func remoteEndpointHasPort(endpoint string) bool {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return false
	}
	if host, portText, err := net.SplitHostPort(trimmed); err == nil {
		_ = host
		portValue, parseErr := strconv.Atoi(strings.TrimSpace(portText))
		return parseErr == nil && portValue > 0 && portValue < 65536
	}
	// Fallback for malformed-but-common values, e.g. "host:1234:1234".
	lastColon := strings.LastIndex(trimmed, ":")
	if lastColon <= 0 || lastColon >= len(trimmed)-1 {
		return false
	}
	portValue, parseErr := strconv.Atoi(strings.TrimSpace(trimmed[lastColon+1:]))
	return parseErr == nil && portValue > 0 && portValue < 65536
}

func (r *Registry) resolveTCPRemoteDomainLocked() string {
	if r.resources == nil {
		return ""
	}
	if assigned := strings.TrimSpace(r.resources.GetAssignedDomain()); assigned != "" {
		return assigned
	}
	return strings.TrimSpace(r.resources.GetCustomDomain())
}

func isAddrAlreadyInUseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use")
}

// Close
func (r *Registry) Close(targetID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	target, ok := r.targets[targetID]
	if !ok {
		return fmt.Errorf("target not found: %s", targetID)
	}

	return r.closeLocked(target)
}

// Handle
func (r *Registry) HandleDataPacket(channelID, connectionID string, seq uint32, data []byte, flags uint8) error {
	r.mu.RLock()
	target, ok := r.targets[channelID]
	var runtime ChannelRuntime
	if ok {
		runtime = r.runtimes[target.Type]
	}
	r.mu.RUnlock()

	if !ok {
		return fmt.Errorf("target not found: %s", channelID)
	}
	if runtime == nil {
		return fmt.Errorf("unsupported channel type for data packet: %v", target.Type)
	}
	return runtime.HandleData(target, connectionID, seq, data, flags)
}

// Close
func (r *Registry) CloseBySession(sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	targetIDs := r.sessionTargets[sessionID]
	for _, id := range targetIDs {
		if target, ok := r.targets[id]; ok {
			r.closeLocked(target)
		}
	}
}

// TouchSessionChannels persists activity for channels that belong to the
// specified transport session. This keeps CLI LastActiveAt aligned with
// control-plane liveness rather than data-plane traffic.
func (r *Registry) TouchSessionChannels(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}

	r.mu.RLock()
	targetIDs := append([]string(nil), r.sessionTargets[sessionID]...)
	r.mu.RUnlock()
	if len(targetIDs) == 0 {
		return
	}

	now := time.Now()
	for _, channelID := range targetIDs {
		r.touchChannelActivity(channelID, now)
	}
}

func (r *Registry) touchChannelActivity(channelID string, now time.Time) {
	if channelID == "" {
		return
	}

	var store *ChannelStore
	shouldPersist := false

	r.mu.Lock()
	store = r.store
	if store != nil {
		if _, exists := r.targets[channelID]; exists {
			lastPersistedAt := r.lastPersistedActivityAt[channelID]
			if lastPersistedAt.IsZero() || now.Sub(lastPersistedAt) >= channelActivityPersistMinInterval {
				r.lastPersistedActivityAt[channelID] = now
				shouldPersist = true
			}
		} else {
			delete(r.lastPersistedActivityAt, channelID)
		}
	}
	r.mu.Unlock()

	if !shouldPersist || store == nil {
		return
	}

	if err := store.UpdateActivity(context.Background(), channelID); err != nil {
		logger.Warnf("failed to update channel activity, channel=%s, err=%v", channelID, err)
		r.mu.Lock()
		delete(r.lastPersistedActivityAt, channelID)
		r.mu.Unlock()
	}
}

// Close
func (r *Registry) closeLocked(target *Channel) error {
	target.SetState(StateClosing)

	switch target.Type {
	case fbMsg.ChannelTypeHTTP, fbMsg.ChannelTypeHTTPS:
		r.closeHTTPResourcesLocked(target)

	case fbMsg.ChannelTypeTCP:
		if target.Port > 0 {
			r.resources.ReleaseTCP(target.Port)
			delete(r.portTargets, portTargetMapKey(target.Type, target.Port))
		}

	case fbMsg.ChannelTypeUDP, fbMsg.ChannelTypeWIREGUARD:
		if target.Port > 0 {
			r.resources.ReleaseUDP(target.Port)
			delete(r.portTargets, portTargetMapKey(target.Type, target.Port))
		}

		// case fbMsg.ChannelTypeLOG:
		// 	// Nothing to release
	}
	r.removeRuntimeLocked(target)
	r.forgetPortShareHintByTargetLocked(target.ID, target.Port)
	delete(r.lastPersistedActivityAt, target.ID)
	target.SetState(StateClosed)

	// Remove
	delete(r.targets, target.ID)
	r.removeFromSession(target.SessionID, target.ID)

	logger.Infof("target closed: id=%s, type=%v", target.ID, target.Type)
	return nil
}

// Remove
func (r *Registry) removeFromSession(sessionID, targetID string) {
	ids := r.sessionTargets[sessionID]
	for i, id := range ids {
		if id == targetID {
			r.sessionTargets[sessionID] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	if len(r.sessionTargets[sessionID]) == 0 {
		delete(r.sessionTargets, sessionID)
	}
}

// Method

// Get
func (r *Registry) Get(targetID string) *Channel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.targets[targetID]
}

// Get
func (r *Registry) GetByDomain(domain string) *Channel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil
	}
	if id, ok := r.domainTargets[aliasRouteKey(domain)]; ok {
		return r.targets[id]
	}
	subdomain := domain
	if idx := strings.Index(subdomain, "."); idx > 0 {
		subdomain = subdomain[:idx]
	}
	if id, ok := r.domainTargets[subdomainRouteKey(subdomain)]; ok {
		return r.targets[id]
	}
	return nil
}

// Get
func (r *Registry) GetByPort(port uint16) *Channel {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, channelType := range []fbMsg.ChannelType{
		fbMsg.ChannelTypeTCP,
		fbMsg.ChannelTypeUDP,
		fbMsg.ChannelTypeWIREGUARD,
	} {
		if id, ok := r.portTargets[portTargetMapKey(channelType, port)]; ok {
			if target, exists := r.targets[id]; exists {
				return target
			}
		}
	}
	return nil
}

// Get
func (r *Registry) GetBySession(sessionID string) []*Channel {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var targets []*Channel
	for _, id := range r.sessionTargets[sessionID] {
		if t, ok := r.targets[id]; ok {
			targets = append(targets, t)
		}
	}
	return targets
}

// Get
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.targets)
}

// Stats
func (r *Registry) CountByType() map[fbMsg.ChannelType]int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	counts := make(map[fbMsg.ChannelType]int)
	for _, t := range r.targets {
		counts[t.Type]++
	}
	return counts
}

// Get
func (r *Registry) GetAllStats() map[string]ChannelStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := make(map[string]ChannelStats)
	for id, t := range r.targets {
		stats[id] = t.GetStats()
	}
	return stats
}

// GetResources returns the resource pool.
func (r *Registry) GetResources() *ResourcePool {
	return r.resources
}

// GetAllTargets returns a snapshot of all current targets.
func (r *Registry) GetAllTargets() map[string]*Channel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]*Channel, len(r.targets))
	for k, v := range r.targets {
		result[k] = v
	}
	return result
}

// UpdateTargetDataPath updates dataplane projection fields for one target.
// Empty linkType/remoteEndpoint values are treated as "no update" for that field.
func (r *Registry) UpdateTargetDataPath(targetID, linkType, remoteEndpoint string) bool {
	targetID = strings.TrimSpace(targetID)
	if r == nil || targetID == "" {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	target, ok := r.targets[targetID]
	if !ok || target == nil {
		return false
	}

	changed := false
	if raw := strings.TrimSpace(linkType); raw != "" {
		normalizedLinkType := normalizeTunnelLinkType(raw)
		if target.LinkType != normalizedLinkType {
			target.LinkType = normalizedLinkType
			changed = true
		}
	}
	if endpoint := strings.TrimSpace(remoteEndpoint); endpoint != "" && target.RemoteEndpoint != endpoint {
		target.RemoteEndpoint = endpoint
		changed = true
	}
	return changed
}
