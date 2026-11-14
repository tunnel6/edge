package handler

import (
	"testing"

	"icool.io/yat/edge/pkg/config"
)

func TestFilterTunnelChallenges_PrefersAliasDomainScope(t *testing.T) {
	tunnelAliasDomains := map[string]struct{}{
		"bj.youxiner.com": {},
	}
	challenges := []DNS01ChallengeStatusInfo{
		{
			RecordName:  "_acme-challenge.another.example.com",
			RecordValue: "txt-visible",
			Domain:      "another.example.com",
		},
		{
			RecordName:  "_acme-challenge.bj.youxiner.com",
			RecordValue: "txt-alias",
			Domain:      "bj.youxiner.com",
		},
	}

	filtered := filterTunnelChallenges(tunnelAliasDomains, challenges)
	if len(filtered) != 1 {
		t.Fatalf("filtered count mismatch: got=%d want=%d", len(filtered), 1)
	}
	if filtered[0].RecordValue != "txt-alias" {
		t.Fatalf("record value mismatch: got=%q want=%q", filtered[0].RecordValue, "txt-alias")
	}
}

func TestFilterTunnelChallenges_MatchByRecordNameTarget(t *testing.T) {
	tunnelAliasDomains := map[string]struct{}{
		"bj.youxiner.com": {},
	}
	challenges := []DNS01ChallengeStatusInfo{
		{
			RecordName:  "_acme-challenge.bj.youxiner.com",
			RecordValue: "txt-from-record-name",
			Domain:      "",
		},
	}

	filtered := filterTunnelChallenges(tunnelAliasDomains, challenges)
	if len(filtered) != 1 {
		t.Fatalf("filtered count mismatch: got=%d want=%d", len(filtered), 1)
	}
	if filtered[0].RecordValue != "txt-from-record-name" {
		t.Fatalf("record value mismatch: got=%q want=%q", filtered[0].RecordValue, "txt-from-record-name")
	}
}

func TestFilterTunnelChallenges_NoFallbackWhenAliasScopeMissing(t *testing.T) {
	tunnelAliasDomains := map[string]struct{}{
		"bj.youxiner.com": {},
	}
	challenges := []DNS01ChallengeStatusInfo{
		{
			RecordName:  "_acme-challenge.another.example.com",
			RecordValue: "txt-visible",
			Domain:      "another.example.com",
		},
	}

	filtered := filterTunnelChallenges(tunnelAliasDomains, challenges)
	if len(filtered) != 0 {
		t.Fatalf("filtered count mismatch: got=%d want=%d", len(filtered), 0)
	}
}

type stubDNS01ChallengeProvider struct {
	challenges []DNS01ChallengeStatusInfo
}

func (s stubDNS01ChallengeProvider) GetActiveDNS01Challenges() []DNS01ChallengeStatusInfo {
	if len(s.challenges) == 0 {
		return nil
	}
	out := make([]DNS01ChallengeStatusInfo, len(s.challenges))
	copy(out, s.challenges)
	return out
}

type stubDomainStatusProvider struct {
	assignedStatus    DomainStatusInfo
	customStatus      DomainStatusInfo
	channelStatusBy   map[string]DomainStatusInfo
	aliasStatusByHost map[string]DomainStatusInfo
}

func (s stubDomainStatusProvider) GetAssignedDomainStatus() DomainStatusInfo {
	return s.assignedStatus
}

func (s stubDomainStatusProvider) GetCustomDomainStatus() DomainStatusInfo {
	return s.customStatus
}

func (s stubDomainStatusProvider) GetChannelDomainStatus(channelDomain string) DomainStatusInfo {
	if s.channelStatusBy == nil {
		return DomainStatusInfo{}
	}
	return s.channelStatusBy[channelDomain]
}

func (s stubDomainStatusProvider) GetChannelAliasDomainStatus(aliasDomain, _ string) DomainStatusInfo {
	if s.aliasStatusByHost == nil {
		return DomainStatusInfo{}
	}
	return s.aliasStatusByHost[aliasDomain]
}

func assertDomainStatusEqual(t *testing.T, got, want DomainStatusInfo, label string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s mismatch: got=%+v want=%+v", label, got, want)
	}
}

func TestBuildTunnelStatusInfo_DNS01CarriesTXTRecordValue(t *testing.T) {
	ctx := &Context{
		DNS01ChallengeProvider: stubDNS01ChallengeProvider{
			challenges: []DNS01ChallengeStatusInfo{
				{
					RecordName:  "_acme-challenge.bj.youxiner.com",
					RecordValue: "txt-token-1",
					Domain:      "bj.youxiner.com",
				},
				{
					RecordName:  "_acme-challenge.other.example.com",
					RecordValue: "txt-token-2",
					Domain:      "other.example.com",
				},
			},
		},
	}

	status := &EdgeServiceStatus{
		EdgeID: "edge-1",
		Online: true,
		Channels: []ChannelStatus{
			{
				ID:          "tun-1:http",
				SessionID:   "sess-1",
				UserID:      "user-1",
				AliasDomain: "bj.youxiner.com",
				Domain:      "abc.edge.example.com",
				State:       "active",
			},
		},
	}

	info := buildTunnelStatusInfo(ctx, status, true, "tun-1")
	if !info.Success {
		t.Fatalf("tunnel status should be success, got error_code=%d error_message=%q", info.ErrorCode, info.ErrorMessage)
	}
	if len(info.DNS01Challenges) != 1 {
		t.Fatalf("dns01 challenge count mismatch: got=%d want=%d", len(info.DNS01Challenges), 1)
	}
	if info.DNS01Challenges[0].RecordName != "_acme-challenge.bj.youxiner.com" {
		t.Fatalf("record name mismatch: got=%q want=%q", info.DNS01Challenges[0].RecordName, "_acme-challenge.bj.youxiner.com")
	}
	if info.DNS01Challenges[0].RecordValue != "txt-token-1" {
		t.Fatalf("record value mismatch: got=%q want=%q", info.DNS01Challenges[0].RecordValue, "txt-token-1")
	}

	if len(info.DomainRuntime.RequiredRecords) != 2 {
		t.Fatalf("required records mismatch: got=%d want=%d", len(info.DomainRuntime.RequiredRecords), 2)
	}
	if info.DomainRuntime.RequiredRecords[0].RecordType != DomainRecordTypeCNAME {
		t.Fatalf("required record type mismatch: got=%d want=%d", info.DomainRuntime.RequiredRecords[0].RecordType, DomainRecordTypeCNAME)
	}
	if info.DomainRuntime.RequiredRecords[0].RecordName != "bj.youxiner.com" {
		t.Fatalf("required cname record name mismatch: got=%q want=%q", info.DomainRuntime.RequiredRecords[0].RecordName, "bj.youxiner.com")
	}
	if info.DomainRuntime.RequiredRecords[0].RecordValue != "abc.edge.example.com" {
		t.Fatalf("required cname record value mismatch: got=%q want=%q", info.DomainRuntime.RequiredRecords[0].RecordValue, "abc.edge.example.com")
	}
	if info.DomainRuntime.RequiredRecords[1].RecordType != DomainRecordTypeTXT {
		t.Fatalf("required record type mismatch: got=%d want=%d", info.DomainRuntime.RequiredRecords[1].RecordType, DomainRecordTypeTXT)
	}
	if info.DomainRuntime.RequiredRecords[1].RecordValue != "txt-token-1" {
		t.Fatalf("required record value mismatch: got=%q want=%q", info.DomainRuntime.RequiredRecords[1].RecordValue, "txt-token-1")
	}
}

func TestBuildTunnelStatusInfo_DNS01DoesNotFallbackToCustomDomainScope(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Channel.SetCustomDomain("fuck4.youxiner.com")

	ctx := &Context{
		Config: cfg,
		DNS01ChallengeProvider: stubDNS01ChallengeProvider{
			challenges: []DNS01ChallengeStatusInfo{
				{
					RecordName:  "_acme-challenge.fuck4.youxiner.com",
					RecordValue: "txt-token-custom-domain",
					Domain:      "fuck4.youxiner.com",
				},
			},
		},
	}

	status := &EdgeServiceStatus{
		EdgeID: "edge-1",
		Online: true,
		Channels: []ChannelStatus{
			{
				ID:          "tun-2:http",
				SessionID:   "sess-1",
				UserID:      "user-1",
				AliasDomain: "",
				Domain:      "abc.edge.example.com",
				State:       "active",
			},
		},
	}

	info := buildTunnelStatusInfo(ctx, status, true, "tun-2")
	if !info.Success {
		t.Fatalf("tunnel status should be success, got error_code=%d error_message=%q", info.ErrorCode, info.ErrorMessage)
	}
	if len(info.DNS01Challenges) != 0 {
		t.Fatalf("dns01 challenge count mismatch: got=%d want=%d", len(info.DNS01Challenges), 0)
	}
}

func TestBuildTunnelStatusInfo_CustomDNSStatusUsesProviderOnly(t *testing.T) {
	customStatus := DomainStatusInfo{
		DNSStatus:     1,
		CertStatus:    2,
		Error:         "custom-status-error",
		CertLastError: "custom-cert-error",
		UpdatedAt:     888,
	}
	aliasStatus := DomainStatusInfo{
		DNSStatus:     0,
		CertStatus:    1,
		Error:         "alias-status-error",
		CertLastError: "alias-cert-error",
		UpdatedAt:     999,
	}
	ctx := &Context{
		DomainStatusProvider: stubDomainStatusProvider{
			customStatus: customStatus,
			aliasStatusByHost: map[string]DomainStatusInfo{
				"alias.youxiner.com": aliasStatus,
			},
		},
	}

	status := &EdgeServiceStatus{
		EdgeID: "edge-1",
		Online: true,
		Channels: []ChannelStatus{
			{
				ID:          "tun-3:http",
				SessionID:   "sess-1",
				UserID:      "user-1",
				AliasDomain: "alias.youxiner.com",
				Domain:      "abc.edge.example.com",
				State:       "active",
			},
		},
	}

	info := buildTunnelStatusInfo(ctx, status, true, "tun-3")
	if !info.Success {
		t.Fatalf("tunnel status should be success, got error_code=%d error_message=%q", info.ErrorCode, info.ErrorMessage)
	}
	assertDomainStatusEqual(t, info.CustomDNSStatus, customStatus, "custom domain status")
	assertDomainStatusEqual(t, info.Channels[0].AliasDomainStatus, aliasStatus, "channel alias domain status")
	if info.CnameStatus != 0 {
		t.Fatalf("cname status should follow alias domain dns status signal, got=%d want=%d", info.CnameStatus, 0)
	}
	if info.DomainRuntime.CertStatus != aliasStatus.CertStatus {
		t.Fatalf("domain runtime cert status should follow alias status, got=%d want=%d", info.DomainRuntime.CertStatus, aliasStatus.CertStatus)
	}
	if info.DomainRuntime.State != DomainRuntimeStateCNAMERequired {
		t.Fatalf("domain runtime state mismatch: got=%d want=%d", info.DomainRuntime.State, DomainRuntimeStateCNAMERequired)
	}
}

func TestBuildTunnelStatusInfo_CustomDNSStatusUnknownDoesNotBorrowAlias(t *testing.T) {
	customStatus := DomainStatusInfo{}
	aliasStatus := DomainStatusInfo{
		DNSStatus:     1,
		CertStatus:    2,
		Error:         "alias-status-error",
		CertLastError: "alias-cert-error",
		UpdatedAt:     777,
	}
	ctx := &Context{
		DomainStatusProvider: stubDomainStatusProvider{
			customStatus: customStatus,
			aliasStatusByHost: map[string]DomainStatusInfo{
				"alias.youxiner.com": aliasStatus,
			},
		},
	}

	status := &EdgeServiceStatus{
		EdgeID: "edge-1",
		Online: true,
		Channels: []ChannelStatus{
			{
				ID:          "tun-4:http",
				SessionID:   "sess-1",
				UserID:      "user-1",
				AliasDomain: "alias.youxiner.com",
				Domain:      "abc.edge.example.com",
				State:       "active",
			},
		},
	}

	info := buildTunnelStatusInfo(ctx, status, true, "tun-4")
	if !info.Success {
		t.Fatalf("tunnel status should be success, got error_code=%d error_message=%q", info.ErrorCode, info.ErrorMessage)
	}
	assertDomainStatusEqual(t, info.CustomDNSStatus, customStatus, "custom domain status")
	assertDomainStatusEqual(t, info.Channels[0].AliasDomainStatus, aliasStatus, "channel alias domain status")
	if info.CnameStatus != 2 {
		t.Fatalf("cname status should be matched when alias dns status is ready, got=%d want=%d", info.CnameStatus, 2)
	}
	if info.DomainRuntime.CertStatus != aliasStatus.CertStatus {
		t.Fatalf("domain runtime cert status should follow alias status, got=%d want=%d", info.DomainRuntime.CertStatus, aliasStatus.CertStatus)
	}
	if info.DomainRuntime.State != DomainRuntimeStateFailed {
		t.Fatalf("domain runtime state mismatch: got=%d want=%d", info.DomainRuntime.State, DomainRuntimeStateFailed)
	}
}

func TestBuildTunnelStatusInfo_CnameStatusUsesWorstAliasSignalAcrossChannels(t *testing.T) {
	aliasReady := DomainStatusInfo{
		DNSStatus:  1,
		CertStatus: 1,
	}
	aliasMismatch := DomainStatusInfo{
		DNSStatus:  2,
		CertStatus: 2,
		Error:      "cname mismatch",
	}
	ctx := &Context{
		DomainStatusProvider: stubDomainStatusProvider{
			aliasStatusByHost: map[string]DomainStatusInfo{
				"ok.example.com":   aliasReady,
				"bad.example.com":  aliasMismatch,
				"noop.example.com": {},
			},
		},
	}

	status := &EdgeServiceStatus{
		EdgeID: "edge-1",
		Online: true,
		Channels: []ChannelStatus{
			{
				ID:          "tun-5:http",
				SessionID:   "sess-1",
				UserID:      "user-1",
				AliasDomain: "ok.example.com",
				Domain:      "ok.edge.example.com",
				State:       "active",
			},
			{
				ID:          "tun-5:https",
				SessionID:   "sess-1",
				UserID:      "user-1",
				AliasDomain: "bad.example.com",
				Domain:      "bad.edge.example.com",
				State:       "active",
			},
		},
	}

	info := buildTunnelStatusInfo(ctx, status, true, "tun-5")
	if !info.Success {
		t.Fatalf("tunnel status should be success, got error_code=%d error_message=%q", info.ErrorCode, info.ErrorMessage)
	}
	if info.CnameStatus != cnameStatusMismatch {
		t.Fatalf("cname status mismatch: got=%d want=%d", info.CnameStatus, cnameStatusMismatch)
	}
	if info.DomainRuntime.State != DomainRuntimeStateCNAMERequired {
		t.Fatalf("domain runtime state mismatch: got=%d want=%d", info.DomainRuntime.State, DomainRuntimeStateCNAMERequired)
	}
	if len(info.DomainRuntime.RequiredRecords) != 2 {
		t.Fatalf("required records mismatch: got=%d want=%d", len(info.DomainRuntime.RequiredRecords), 2)
	}
}

func TestStatusProjectionKeepsCapabilitiesAndSeparatesRoles(t *testing.T) {
	cfg := &config.Config{Proxy: config.ProxyConfig{
		HTTP: &config.HTTPProxyConfig{Enabled: true, Port: 18080, HTTPSPort: 18443},
		TCP:  &config.TCPProxyConfig{Enabled: true, PortMin: 22000, PortMax: 23000},
	}}
	ctx := &Context{Config: cfg}
	ctx.UserID = "device:a"
	source := &EdgeServiceStatus{EdgeID: "edge-a", Online: true, Stats: ServiceStats{ActiveSessions: 4}}
	owner := BuildEdgeStatusInfo(ctx, source, true)
	device := BuildEdgeStatusInfo(ctx, source, false)
	if len(owner.SupportedProtocols) != 3 || len(device.SupportedProtocols) != 3 {
		t.Fatal("status lost capabilities")
	}
	if owner.PortUsage.HTTPPort != 18080 || device.PortUsage.HTTPSPort != 18443 || device.PortUsage.TCPRange != "22000-23000" {
		t.Fatal("status invented ports")
	}
	if !owner.IsOwnerView || owner.ActiveSessions != 4 {
		t.Fatal("owner view lost")
	}
	if device.IsOwnerView || device.ActiveSessions != 0 {
		t.Fatal("device saw owner-only sessions")
	}
	if source.Stats.ActiveSessions != 4 {
		t.Fatal("per-session projection mutated shared snapshot")
	}
}
