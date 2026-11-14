package server

import (
	"encoding/json"
	"fmt"
	"strings"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/pkg/config"
)

func applyManagementOptions(m *config.ManagementConfig, cfg *config.Config, opts *serverOptions) {
	if v := m.Channel.HTTP.Enable; v != nil {
		WithHTTPProxyEnabled(*v)(opts)
	}
	if v := m.Channel.HTTP.Port; v != nil {
		WithRegistryHTTPPort(*v)(opts)
		WithHTTPProxyAddr(fmt.Sprintf(":%d", *v))(opts)
	}
	if v := m.Channel.HTTP.HTTPSPort; v != nil {
		WithRegistryHTTPSPort(*v)(opts)
	}
	if v := m.Channel.TCP.Enable; v != nil {
		WithTCPProxyEnabled(*v)(opts)
	}
	if m.Channel.TCP.PortMin != nil || m.Channel.TCP.PortMax != nil {
		WithTCPPortRange(cfg.Proxy.TCP.PortMin, cfg.Proxy.TCP.PortMax)(opts)
	}
	if v := m.Channel.UDP.Enable; v != nil {
		WithUDPProxyEnabled(*v)(opts)
	}
	if m.Channel.UDP.PortMin != nil || m.Channel.UDP.PortMax != nil {
		WithUDPPortRange(cfg.Proxy.UDP.PortMin, cfg.Proxy.UDP.PortMax)(opts)
	}
	if v := m.Channel.WireGuard.Enable; v != nil {
		WithWireGuardEnabled(*v)(opts)
	}
	if v := m.Node.PublicAddress; v != nil {
		WithNodePublicAddress(*v)(opts)
	}
	if v := m.Server.Capabilities.AutoEnable; v != nil {
		WithAutoEnableFromCapabilities(*v)(opts)
	}
	if v := m.Server.Capabilities.P2P; v != nil {
		WithP2PEnabled(*v)(opts)
	}
}

// managementConfig returns saved desired values; runtime-only credentials never
// leave the Edge. Pending listener changes remain visible until the restart.
func (s *Server) managementConfig() (*config.ManagementConfig, *config.ManagementConfig, error) {
	current := s.config.ManagementSnapshot()
	// Constructor options can override the deployment config before any managed
	// file exists. Read and persist the values actually used by components.
	if v := s.opts.registryHTTPPort; v != nil {
		current.Channel.HTTP.Port = v
	}
	if v := s.opts.registryHTTPSPort; v != nil {
		current.Channel.HTTP.HTTPSPort = v
	}
	if v := s.opts.resourceTCPPortMin; v != nil {
		current.Channel.TCP.PortMin = v
	}
	if v := s.opts.resourceTCPPortMax; v != nil {
		current.Channel.TCP.PortMax = v
	}
	if v := s.opts.resourceUDPPortMin; v != nil {
		current.Channel.UDP.PortMin = v
	}
	if v := s.opts.resourceUDPPortMax; v != nil {
		current.Channel.UDP.PortMax = v
	}
	if v := s.opts.nodePublicAddress; v != nil {
		current.Node.PublicAddress = v
	}
	autoEnable := s.opts.autoEnableFromCapabilities
	current.Server.Capabilities.AutoEnable = &autoEnable
	if s.opts.p2pEnabledSet {
		p2p := s.opts.p2pEnabled
		current.Server.Capabilities.P2P = &p2p
	}
	saved, err := config.LoadManagementConfig(s.config.GetDataDir())
	if err != nil {
		return nil, nil, err
	}
	return current, current.Merge(saved), nil
}

func (s *Server) updateManagementConfig(raw string) (*config.ManagementConfig, bool, error) {
	s.managementMu.Lock()
	defer s.managementMu.Unlock()
	current, desired, err := s.managementConfig()
	if err != nil {
		return nil, false, err
	}
	if strings.TrimSpace(raw) != "" {
		if len(raw) > 64*1024 {
			return nil, false, fmt.Errorf("management config exceeds 64 KiB")
		}
		patch, err := config.DecodeManagementConfig([]byte(raw))
		if err != nil {
			return nil, false, err
		}
		desired = desired.Merge(patch)
		if err := desired.Validate(); err != nil {
			return nil, false, err
		}
		if err := config.SaveManagementConfig(s.config.GetDataDir(), desired); err != nil {
			return nil, false, fmt.Errorf("persist Edge configuration: %w", err)
		}
		desired.ApplyLive(s.config)
	}
	return desired, desired.RestartRequired(current), nil
}

func (s *Server) handleEdgeConfigRequest(session *Session, msg *fb.Message) error {
	seq := msg.Header(nil).Seq()
	session.mu.RLock()
	restricted := len(session.ScopeClaims) > 0
	session.mu.RUnlock()
	if !(sessionOwnerVerifier{session: session}).IsEdgeOwner(session.UserID) || restricted {
		return session.Protocol.sendEdgeConfigResponse(session, seq, nil, false, fmt.Errorf("permission denied: unrestricted Edge owner required"))
	}
	var table flatbuffers.Table
	if !msg.Body(&table) || msg.BodyType() != fb.MessageBodyEdgeConfigRequest {
		return session.Protocol.sendEdgeConfigResponse(session, seq, nil, false, fmt.Errorf("missing Edge config request"))
	}
	var request fb.EdgeConfigRequest
	request.Init(table.Bytes, table.Pos)
	desired, restart, err := s.updateManagementConfig(string(request.ConfigJson()))
	return session.Protocol.sendEdgeConfigResponse(session, seq, desired, restart, err)
}

func (p *Protocol) sendEdgeConfigResponse(session *Session, seq uint32, desired *config.ManagementConfig, restart bool, responseErr error) error {
	response := &fb.EdgeConfigResponseT{Success: responseErr == nil, RestartRequired: restart}
	if responseErr != nil {
		response.ErrorMessage = responseErr.Error()
	} else {
		raw, err := json.Marshal(desired)
		if err != nil {
			return err
		}
		response.ConfigJson = string(raw)
	}
	builder := flatbuffers.NewBuilder(512)
	message := &fb.MessageT{Header: &fb.MessageHeaderT{Type: fb.MessageTypeEDGE_CONFIG_RESPONSE, Seq: seq, SessionId: session.ID},
		Body: &fb.MessageBodyT{Type: fb.MessageBodyEdgeConfigResponse, Value: response}}
	builder.Finish(message.Pack(builder))
	return p.WriteMessage(session.Conn, builder.FinishedBytes())
}
