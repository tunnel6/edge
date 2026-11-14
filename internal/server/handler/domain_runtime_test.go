package handler

import (
	"testing"

	"icool.io/yat/edge/pkg/config"
)

func makeDomainRuntimeTestContext(customDomain, assignedDomain string) *Context {
	cfg := config.DefaultConfig()
	cfg.Channel.SetCustomDomain(customDomain)
	cfg.Channel.SetAssignedDomain(assignedDomain)
	return &Context{Config: cfg}
}

func TestStandaloneBaseDomainRuntime(t *testing.T) {
	ctx := makeDomainRuntimeTestContext("", "files.example.com")
	ctx.Config.Channel.BaseDomain = "files.example.com"
	ctx.Config.Node.PublicAddress = "203.0.113.10"
	status := DomainStatusInfo{DNSStatus: 2, CertStatus: 2}
	challenge := DNS01ChallengeStatusInfo{RecordName: "_acme-challenge.files.example.com", RecordValue: "token", Domain: "*.files.example.com"}
	ctx.DomainStatusProvider = stubDomainStatusProvider{assignedStatus: status, customStatus: status}
	ctx.DNS01ChallengeProvider = stubDNS01ChallengeProvider{challenges: []DNS01ChallengeStatusInfo{challenge}}
	info := BuildEdgeStatusInfo(ctx, &EdgeServiceStatus{}, true)
	if len(info.DNS01Challenges) != 1 {
		t.Fatal("base-domain DNS-01 challenge was filtered out")
	}
	if info.DomainRuntime.State != DomainRuntimeStateCNAMEAndTXT || len(info.DomainRuntime.RequiredRecords) != 2 {
		t.Fatalf("missing routing/TXT guidance: %+v", info.DomainRuntime)
	}
	record := info.DomainRuntime.RequiredRecords[0]
	if record.RecordType != DomainRecordTypeA || record.RecordName != "*.files.example.com" || record.RecordValue != "203.0.113.10" {
		t.Fatalf("wrong wildcard A record: %+v", record)
	}
	ctx.Config.Node.PublicAddress = "2001:db8::1"
	state := buildDomainRuntimeInfo(ctx, true, 0, status, []DNS01ChallengeStatusInfo{challenge})
	if state.RequiredRecords[0].RecordType != DomainRecordTypeAAAA {
		t.Fatal("expected AAAA guidance")
	}
	ctx.Config.Proxy.HTTP.HTTPSPort = 0
	state = buildDomainRuntimeInfo(ctx, true, 2, DomainStatusInfo{DNSStatus: 1}, nil)
	if state.State != DomainRuntimeStateHealthy {
		t.Fatalf("HTTP-only deployment should not require a certificate: %+v", state)
	}
	ctx.Config.Proxy.HTTP.HTTPSPort = 443
	state = buildDomainRuntimeInfo(ctx, true, 2, DomainStatusInfo{DNSStatus: 1, CertStatus: 2}, []DNS01ChallengeStatusInfo{challenge})
	if state.State != DomainRuntimeStateTXTRequired {
		t.Fatalf("expected DNS-01 guidance: %+v", state)
	}
	ctx.Config.Proxy.HTTP.CertificateSource = "upload"
	state = buildDomainRuntimeInfo(ctx, true, 2, DomainStatusInfo{DNSStatus: 1, CertStatus: 2}, nil)
	if state.PendingReasonCode != "certificate_upload_required" || len(state.RequiredRecords) != 0 {
		t.Fatalf("expected upload guidance without TXT records: %+v", state)
	}
}

func TestBuildDomainRuntimeInfo_StateMatrix(t *testing.T) {
	challenge := DNS01ChallengeStatusInfo{
		RecordName:  "_acme-challenge.bj.youxiner.com",
		RecordValue: "txt-token",
		Domain:      "bj.youxiner.com",
		CreatedAt:   1100,
		LastError:   "",
		UpdatedAt:   1200,
	}

	tests := []struct {
		name                string
		ctx                 *Context
		isOwner             bool
		cnameStatus         uint8
		customStatus        DomainStatusInfo
		challenges          []DNS01ChallengeStatusInfo
		wantState           uint8
		wantPendingReason   string
		wantRequiredRecords int
	}{
		{
			name:        "healthy_when_cert_ready_and_cname_ok",
			ctx:         makeDomainRuntimeTestContext("bj.youxiner.com", "c.e.myproxy.dev"),
			isOwner:     true,
			cnameStatus: 2,
			customStatus: DomainStatusInfo{
				CertStatus: 1,
			},
			wantState:           DomainRuntimeStateHealthy,
			wantPendingReason:   "",
			wantRequiredRecords: 0,
		},
		{
			name:        "cname_required_generates_cname_record",
			ctx:         makeDomainRuntimeTestContext("bj.youxiner.com", "c.e.myproxy.dev"),
			isOwner:     true,
			cnameStatus: cnameStatusMismatch,
			customStatus: DomainStatusInfo{
				CertStatus: 2,
			},
			wantState:           DomainRuntimeStateCNAMERequired,
			wantPendingReason:   "cname_required",
			wantRequiredRecords: 1,
		},
		{
			name:        "txt_required_owner_sees_txt_records",
			ctx:         makeDomainRuntimeTestContext("bj.youxiner.com", "c.e.myproxy.dev"),
			isOwner:     true,
			cnameStatus: 2,
			customStatus: DomainStatusInfo{
				CertStatus: 2,
			},
			challenges:          []DNS01ChallengeStatusInfo{challenge},
			wantState:           DomainRuntimeStateTXTRequired,
			wantPendingReason:   "dns01_required",
			wantRequiredRecords: 1,
		},
		{
			name:        "cert_ready_ignores_stale_txt_challenge",
			ctx:         makeDomainRuntimeTestContext("bj.youxiner.com", "c.e.myproxy.dev"),
			isOwner:     true,
			cnameStatus: 2,
			customStatus: DomainStatusInfo{
				CertStatus: 1,
			},
			challenges:          []DNS01ChallengeStatusInfo{challenge},
			wantState:           DomainRuntimeStateHealthy,
			wantPendingReason:   "",
			wantRequiredRecords: 0,
		},
		{
			name:        "txt_required_non_owner_hides_txt_records",
			ctx:         makeDomainRuntimeTestContext("bj.youxiner.com", "c.e.myproxy.dev"),
			isOwner:     false,
			cnameStatus: 2,
			customStatus: DomainStatusInfo{
				CertStatus: 2,
			},
			challenges:          []DNS01ChallengeStatusInfo{challenge},
			wantState:           DomainRuntimeStateTXTRequired,
			wantPendingReason:   "owner_view_required",
			wantRequiredRecords: 0,
		},
		{
			name:        "cname_and_txt_required",
			ctx:         makeDomainRuntimeTestContext("bj.youxiner.com", "c.e.myproxy.dev"),
			isOwner:     true,
			cnameStatus: cnameStatusNotFound,
			customStatus: DomainStatusInfo{
				CertStatus: 2,
			},
			challenges:          []DNS01ChallengeStatusInfo{challenge},
			wantState:           DomainRuntimeStateCNAMEAndTXT,
			wantPendingReason:   "cname_dns01_required",
			wantRequiredRecords: 2,
		},
		{
			name:        "issuing_when_cert_missing_without_error_or_challenge",
			ctx:         makeDomainRuntimeTestContext("bj.youxiner.com", "c.e.myproxy.dev"),
			isOwner:     true,
			cnameStatus: 2,
			customStatus: DomainStatusInfo{
				CertStatus: 2,
			},
			wantState:           DomainRuntimeStateIssuing,
			wantPendingReason:   "cert_issuing",
			wantRequiredRecords: 0,
		},
		{
			name:        "cname_checking_should_still_show_cname_required_for_custom_domain_onboarding",
			ctx:         makeDomainRuntimeTestContext("bj.youxiner.com", "c.e.myproxy.dev"),
			isOwner:     true,
			cnameStatus: 1,
			customStatus: DomainStatusInfo{
				CertStatus: 2,
			},
			wantState:           DomainRuntimeStateCNAMERequired,
			wantPendingReason:   "cname_required",
			wantRequiredRecords: 1,
		},
		{
			name:        "failed_when_cert_missing_with_error",
			ctx:         makeDomainRuntimeTestContext("bj.youxiner.com", "c.e.myproxy.dev"),
			isOwner:     true,
			cnameStatus: 2,
			customStatus: DomainStatusInfo{
				CertStatus:    2,
				CertLastError: "acme challenge failed",
			},
			wantState:           DomainRuntimeStateFailed,
			wantPendingReason:   "cert_failed",
			wantRequiredRecords: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildDomainRuntimeInfo(tc.ctx, tc.isOwner, tc.cnameStatus, tc.customStatus, tc.challenges)
			if got.State != tc.wantState {
				t.Fatalf("state mismatch: got=%d want=%d", got.State, tc.wantState)
			}
			if got.PendingReasonCode != tc.wantPendingReason {
				t.Fatalf("pending reason mismatch: got=%q want=%q", got.PendingReasonCode, tc.wantPendingReason)
			}
			if len(got.RequiredRecords) != tc.wantRequiredRecords {
				t.Fatalf("required records mismatch: got=%d want=%d", len(got.RequiredRecords), tc.wantRequiredRecords)
			}
		})
	}
}

func TestBuildDomainRuntimeInfo_FieldResolution(t *testing.T) {
	ctx := makeDomainRuntimeTestContext("bj.youxiner.com", "c.e.myproxy.dev")
	challenges := []DNS01ChallengeStatusInfo{
		{
			RecordName:  "_acme-challenge.bj.youxiner.com",
			RecordValue: "",
			Domain:      "bj.youxiner.com",
			CreatedAt:   600,
			UpdatedAt:   700,
			LastError:   "challenge-error",
		},
		{
			RecordName:  " _acme-challenge.bj.youxiner.com ",
			RecordValue: " txt-token ",
			Domain:      "bj.youxiner.com",
			CreatedAt:   900,
			UpdatedAt:   1000,
		},
	}

	got := buildDomainRuntimeInfo(ctx, true, cnameStatusMismatch, DomainStatusInfo{
		CertStatus:    2,
		Error:         "domain-status-error",
		CertLastError: "cert-last-error",
		UpdatedAt:     500,
	}, challenges)

	if got.OwnerView != true {
		t.Fatalf("owner_view mismatch: got=%v want=true", got.OwnerView)
	}
	if got.State != DomainRuntimeStateCNAMEAndTXT {
		t.Fatalf("state mismatch: got=%d want=%d", got.State, DomainRuntimeStateCNAMEAndTXT)
	}
	if got.LastError != "cert-last-error" {
		t.Fatalf("last_error mismatch: got=%q want=%q", got.LastError, "cert-last-error")
	}
	if got.UpdatedAt != 1000 {
		t.Fatalf("updated_at mismatch: got=%d want=%d", got.UpdatedAt, 1000)
	}
	if len(got.RequiredRecords) != 2 {
		t.Fatalf("required_records mismatch: got=%d want=%d", len(got.RequiredRecords), 2)
	}

	first := got.RequiredRecords[0]
	if first.RecordType != DomainRecordTypeCNAME {
		t.Fatalf("first record type mismatch: got=%d want=%d", first.RecordType, DomainRecordTypeCNAME)
	}
	if first.RecordName != "*.bj.youxiner.com" {
		t.Fatalf("first record name mismatch: got=%q want=%q", first.RecordName, "*.bj.youxiner.com")
	}
	if first.RecordValue != "c.e.myproxy.dev" {
		t.Fatalf("first record value mismatch: got=%q want=%q", first.RecordValue, "c.e.myproxy.dev")
	}

	second := got.RequiredRecords[1]
	if second.RecordType != DomainRecordTypeTXT {
		t.Fatalf("second record type mismatch: got=%d want=%d", second.RecordType, DomainRecordTypeTXT)
	}
	if second.RecordName != "_acme-challenge.bj.youxiner.com" {
		t.Fatalf("second record name mismatch: got=%q want=%q", second.RecordName, "_acme-challenge.bj.youxiner.com")
	}
	if second.RecordValue != "txt-token" {
		t.Fatalf("second record value mismatch: got=%q want=%q", second.RecordValue, "txt-token")
	}
}

func TestBuildDomainRuntimeInfo_NonOwnerCnameTxtPendingReason(t *testing.T) {
	ctx := makeDomainRuntimeTestContext("bj.youxiner.com", "c.e.myproxy.dev")
	challenges := []DNS01ChallengeStatusInfo{
		{
			RecordName:  "_acme-challenge.bj.youxiner.com",
			RecordValue: "token",
			Domain:      "bj.youxiner.com",
		},
	}

	got := buildDomainRuntimeInfo(ctx, false, cnameStatusMismatch, DomainStatusInfo{CertStatus: 2}, challenges)
	if got.State != DomainRuntimeStateCNAMEAndTXT {
		t.Fatalf("state mismatch: got=%d want=%d", got.State, DomainRuntimeStateCNAMEAndTXT)
	}
	if got.PendingReasonCode != "owner_view_required" {
		t.Fatalf("pending reason mismatch: got=%q want=%q", got.PendingReasonCode, "owner_view_required")
	}
	if len(got.RequiredRecords) != 1 {
		t.Fatalf("required records mismatch: got=%d want=%d", len(got.RequiredRecords), 1)
	}
	if got.RequiredRecords[0].RecordType != DomainRecordTypeCNAME {
		t.Fatalf("record type mismatch: got=%d want=%d", got.RequiredRecords[0].RecordType, DomainRecordTypeCNAME)
	}
}

func TestBuildTunnelAliasDomainRuntimeInfo_UsesAliasSemantics(t *testing.T) {
	routingRecords := []DomainRecordInfo{
		{
			RecordType:  DomainRecordTypeCNAME,
			RecordName:  "alias.example.com",
			RecordValue: "tun.edge.example.com",
			Source:      "routing",
		},
	}
	challenges := []DNS01ChallengeStatusInfo{
		{
			RecordName:  "_acme-challenge.alias.example.com",
			RecordValue: "txt-token",
			Domain:      "alias.example.com",
			UpdatedAt:   800,
		},
	}

	got := buildTunnelAliasDomainRuntimeInfo(
		true,
		cnameStatusMismatch,
		DomainStatusInfo{
			DNSStatus:  2,
			CertStatus: 2,
			UpdatedAt:  500,
		},
		routingRecords,
		challenges,
	)

	if got.State != DomainRuntimeStateCNAMEAndTXT {
		t.Fatalf("state mismatch: got=%d want=%d", got.State, DomainRuntimeStateCNAMEAndTXT)
	}
	if got.PendingReasonCode != "cname_dns01_required" {
		t.Fatalf("pending reason mismatch: got=%q want=%q", got.PendingReasonCode, "cname_dns01_required")
	}
	if len(got.RequiredRecords) != 2 {
		t.Fatalf("required records mismatch: got=%d want=%d", len(got.RequiredRecords), 2)
	}
	if got.RequiredRecords[0].RecordName != "alias.example.com" {
		t.Fatalf("cname record name mismatch: got=%q want=%q", got.RequiredRecords[0].RecordName, "alias.example.com")
	}
	if got.RequiredRecords[0].RecordValue != "tun.edge.example.com" {
		t.Fatalf("cname record value mismatch: got=%q want=%q", got.RequiredRecords[0].RecordValue, "tun.edge.example.com")
	}
	if got.RequiredRecords[1].RecordType != DomainRecordTypeTXT {
		t.Fatalf("txt record type mismatch: got=%d want=%d", got.RequiredRecords[1].RecordType, DomainRecordTypeTXT)
	}
	if got.CertStatus != 2 {
		t.Fatalf("cert status mismatch: got=%d want=%d", got.CertStatus, 2)
	}
	if got.UpdatedAt != 800 {
		t.Fatalf("updated_at mismatch: got=%d want=%d", got.UpdatedAt, 800)
	}
}

func TestBuildTunnelAliasDomainRuntimeInfo_UnknownWhenNoAliasScope(t *testing.T) {
	got := buildTunnelAliasDomainRuntimeInfo(
		true,
		cnameStatusUnknown,
		DomainStatusInfo{},
		nil,
		nil,
	)

	if got.State != DomainRuntimeStateUnknown {
		t.Fatalf("state mismatch: got=%d want=%d", got.State, DomainRuntimeStateUnknown)
	}
	if got.PendingReasonCode != "" {
		t.Fatalf("pending reason mismatch: got=%q want empty", got.PendingReasonCode)
	}
	if len(got.RequiredRecords) != 0 {
		t.Fatalf("required records mismatch: got=%d want=0", len(got.RequiredRecords))
	}
}
