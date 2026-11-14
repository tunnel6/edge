package handler

import (
	"net"
	"strings"
)

const (
	cnameStatusUnknown  uint8 = 0
	cnameStatusChecking uint8 = 1
	cnameStatusMatched  uint8 = 2
	cnameStatusMismatch uint8 = 3
	cnameStatusNotFound uint8 = 4
	cnameStatusError    uint8 = 5
)

// DomainRecordType constants (must match FlatBuffers enum DomainRecordType).
const (
	DomainRecordTypeUnknown uint8 = 0
	DomainRecordTypeCNAME   uint8 = 1
	DomainRecordTypeTXT     uint8 = 2
	DomainRecordTypeA       uint8 = 3
	DomainRecordTypeAAAA    uint8 = 4
)

// DomainRuntimeState constants (must match FlatBuffers enum DomainRuntimeState).
const (
	DomainRuntimeStateUnknown       uint8 = 0
	DomainRuntimeStateHealthy       uint8 = 1
	DomainRuntimeStateCNAMERequired uint8 = 2
	DomainRuntimeStateTXTRequired   uint8 = 3
	DomainRuntimeStateCNAMEAndTXT   uint8 = 4
	DomainRuntimeStateIssuing       uint8 = 5
	DomainRuntimeStateFailed        uint8 = 6
)

// DomainRecordInfo carries directly actionable DNS records for UI.
type DomainRecordInfo struct {
	RecordType  uint8
	RecordName  string
	RecordValue string
	TTL         uint32
	Source      string
}

// DomainRuntimeInfo is backend-authoritative domain/cert runtime state.
type DomainRuntimeInfo struct {
	OwnerView         bool
	State             uint8
	RequiredRecords   []DomainRecordInfo
	PendingReasonCode string
	LastError         string
	CnameStatus       uint8
	CertStatus        uint8
	UpdatedAt         uint64
}

func resolveDomainRuntimeState(
	hasCnameRequired bool,
	hasTXTRequired bool,
	hasCertReady bool,
	hasCertMissing bool,
	lastError string,
) uint8 {
	switch {
	case hasCnameRequired && hasTXTRequired:
		return DomainRuntimeStateCNAMEAndTXT
	case hasCnameRequired:
		return DomainRuntimeStateCNAMERequired
	case hasTXTRequired:
		return DomainRuntimeStateTXTRequired
	case hasCertReady:
		return DomainRuntimeStateHealthy
	case hasCertMissing && lastError != "":
		return DomainRuntimeStateFailed
	case hasCertMissing:
		return DomainRuntimeStateIssuing
	case lastError != "":
		return DomainRuntimeStateFailed
	default:
		return DomainRuntimeStateUnknown
	}
}

func resolveDomainRuntimePendingReasonCode(state uint8, isOwner bool) string {
	switch state {
	case DomainRuntimeStateCNAMERequired:
		return "cname_required"
	case DomainRuntimeStateTXTRequired:
		if isOwner {
			return "dns01_required"
		}
		return "owner_view_required"
	case DomainRuntimeStateCNAMEAndTXT:
		if isOwner {
			return "cname_dns01_required"
		}
		return "owner_view_required"
	case DomainRuntimeStateIssuing:
		return "cert_issuing"
	case DomainRuntimeStateFailed:
		return "cert_failed"
	default:
		return ""
	}
}

func appendTXTChallengeRecords(records []DomainRecordInfo, challenges []DNS01ChallengeStatusInfo) []DomainRecordInfo {
	for _, challenge := range challenges {
		recordName := strings.TrimSpace(challenge.RecordName)
		recordValue := strings.TrimSpace(challenge.RecordValue)
		if recordName == "" || recordValue == "" {
			continue
		}
		records = append(records, DomainRecordInfo{
			RecordType:  DomainRecordTypeTXT,
			RecordName:  recordName,
			RecordValue: recordValue,
			TTL:         0,
			Source:      "dns01_challenge",
		})
	}
	return records
}

func resolveRuntimeLastError(status DomainStatusInfo, challenges []DNS01ChallengeStatusInfo) string {
	lastError := strings.TrimSpace(status.CertLastError)
	if lastError == "" {
		lastError = strings.TrimSpace(status.Error)
	}
	if lastError == "" {
		for _, challenge := range challenges {
			errText := strings.TrimSpace(challenge.LastError)
			if errText != "" {
				lastError = errText
				break
			}
		}
	}
	return lastError
}

func resolveRuntimeUpdatedAt(status DomainStatusInfo, challenges []DNS01ChallengeStatusInfo) uint64 {
	updatedAt := status.UpdatedAt
	for _, challenge := range challenges {
		if challenge.UpdatedAt > updatedAt {
			updatedAt = challenge.UpdatedAt
		}
		if challenge.CreatedAt > updatedAt {
			updatedAt = challenge.CreatedAt
		}
	}
	return updatedAt
}

func buildDomainRuntimeInfo(
	ctx *Context,
	isOwner bool,
	cnameStatus uint8,
	customStatus DomainStatusInfo,
	challenges []DNS01ChallengeStatusInfo,
) DomainRuntimeInfo {
	customDomain := ""
	assignedDomain := ""
	if ctx != nil && ctx.Config != nil {
		customDomain = normalizeChallengeDomain(ctx.Config.Channel.GetCustomDomain())
		assignedDomain = normalizeChallengeDomain(ctx.Config.Channel.GetAssignedDomain())
	}

	// CNAME guidance should be conservative for custom-domain onboarding:
	// as long as custom+assigned domain are present and CNAME has not reached
	// matched state yet, UI should not render as "all good".
	hasCnameRequired := false
	if customDomain != "" && assignedDomain != "" {
		switch cnameStatus {
		case cnameStatusMatched:
			hasCnameRequired = false
		case cnameStatusUnknown, cnameStatusChecking, cnameStatusMismatch, cnameStatusNotFound, cnameStatusError:
			hasCnameRequired = true
		default:
			hasCnameRequired = true
		}
	}
	hasCertReady := customStatus.CertStatus == 1
	hasCertMissing := customStatus.CertStatus == 2
	isLocalBaseDomain := ctx != nil && ctx.Config != nil && ctx.Config.Channel.BaseDomain != "" && customDomain == ""
	if isLocalBaseDomain {
		hasCnameRequired = customStatus.DNSStatus != 1
		if ctx.Config.Proxy.HTTP != nil && ctx.Config.Proxy.HTTP.HTTPSPort == 0 {
			hasCertReady = !hasCnameRequired
			hasCertMissing = false
		}
	}
	// Certificate-ready is the terminal success signal for DNS-01:
	// stale challenge cache should not keep UI in TXT-required state.
	hasTXTRequired := !hasCertReady && len(challenges) > 0

	requiredRecords := make([]DomainRecordInfo, 0, len(challenges)+1)
	if isLocalBaseDomain && hasCnameRequired {
		target := strings.Trim(ctx.Config.Node.PublicAddress, "[]")
		recordType := DomainRecordTypeCNAME
		if ip := net.ParseIP(target); ip != nil {
			recordType = DomainRecordTypeA
			if ip.To4() == nil {
				recordType = DomainRecordTypeAAAA
			}
		}
		requiredRecords = append(requiredRecords, DomainRecordInfo{RecordType: recordType, RecordName: "*." + assignedDomain, RecordValue: target, Source: "routing"})
	}
	if hasCnameRequired && customDomain != "" && assignedDomain != "" {
		requiredRecords = append(requiredRecords, DomainRecordInfo{
			RecordType:  DomainRecordTypeCNAME,
			RecordName:  "*." + customDomain,
			RecordValue: assignedDomain,
			TTL:         0,
			Source:      "routing",
		})
	}
	if isOwner && hasTXTRequired {
		requiredRecords = appendTXTChallengeRecords(requiredRecords, challenges)
	}

	lastError := resolveRuntimeLastError(customStatus, challenges)
	updatedAt := resolveRuntimeUpdatedAt(customStatus, challenges)
	state := resolveDomainRuntimeState(hasCnameRequired, hasTXTRequired, hasCertReady, hasCertMissing, lastError)
	pendingReasonCode := resolveDomainRuntimePendingReasonCode(state, isOwner)
	if isLocalBaseDomain && hasCertMissing && !hasTXTRequired && ctx.Config.Proxy.HTTP.CertificateSource == "upload" {
		pendingReasonCode = "certificate_upload_required"
	}

	return DomainRuntimeInfo{
		OwnerView:         isOwner,
		State:             state,
		RequiredRecords:   requiredRecords,
		PendingReasonCode: pendingReasonCode,
		LastError:         lastError,
		CnameStatus:       cnameStatus,
		CertStatus:        customStatus.CertStatus,
		UpdatedAt:         updatedAt,
	}
}

func buildTunnelAliasDomainRuntimeInfo(
	isOwner bool,
	cnameStatus uint8,
	aliasStatus DomainStatusInfo,
	routingRecords []DomainRecordInfo,
	challenges []DNS01ChallengeStatusInfo,
) DomainRuntimeInfo {
	hasCnameRequired := len(routingRecords) > 0 && cnameStatus != cnameStatusMatched
	hasCertReady := aliasStatus.CertStatus == 1
	hasCertMissing := aliasStatus.CertStatus == 2
	hasTXTRequired := !hasCertReady && len(challenges) > 0

	requiredRecords := make([]DomainRecordInfo, 0, len(routingRecords)+len(challenges))
	if hasCnameRequired {
		requiredRecords = append(requiredRecords, routingRecords...)
	}
	if isOwner && hasTXTRequired {
		requiredRecords = appendTXTChallengeRecords(requiredRecords, challenges)
	}

	lastError := resolveRuntimeLastError(aliasStatus, challenges)
	updatedAt := resolveRuntimeUpdatedAt(aliasStatus, challenges)
	state := resolveDomainRuntimeState(hasCnameRequired, hasTXTRequired, hasCertReady, hasCertMissing, lastError)
	pendingReasonCode := resolveDomainRuntimePendingReasonCode(state, isOwner)

	return DomainRuntimeInfo{
		OwnerView:         isOwner,
		State:             state,
		RequiredRecords:   requiredRecords,
		PendingReasonCode: pendingReasonCode,
		LastError:         lastError,
		CnameStatus:       cnameStatus,
		CertStatus:        aliasStatus.CertStatus,
		UpdatedAt:         updatedAt,
	}
}
