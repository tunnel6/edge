package server

import (
	"testing"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
)

func TestBuildAuthNegotiationResult_ProtocolMajorMismatch(t *testing.T) {
	result := buildAuthNegotiationResult(1, 0, nil, nil, supportedAuthFeatures(false, false, false, false, false, false))
	if result.CompatibilityLevel != fbMsg.CompatibilityLevelCOMPAT_INCOMPATIBLE {
		t.Fatalf("expected incompatible level, got=%v", result.CompatibilityLevel)
	}
	if result.ReasonCode != fbMsg.CompatibilityReasonCodeINCOMPATIBLE_PROTOCOL_MAJOR_MISMATCH {
		t.Fatalf("unexpected reason code, got=%v", result.ReasonCode)
	}
}

func TestBuildAuthNegotiationResult_P2PRequiredRejectedWhenUnsupported(t *testing.T) {
	result := buildAuthNegotiationResult(uint16(fbMsg.ProtocolMajorCURRENT), 0, []string{"p2p.quic"}, nil, supportedAuthFeatures(true, true, true, true, true, false))
	if result.CompatibilityLevel != fbMsg.CompatibilityLevelCOMPAT_INCOMPATIBLE {
		t.Fatalf("expected incompatible level, got=%v", result.CompatibilityLevel)
	}
	if result.ReasonCode != fbMsg.CompatibilityReasonCodeINCOMPATIBLE_REQUIRED_FEATURE_MISSING {
		t.Fatalf("unexpected reason code, got=%v", result.ReasonCode)
	}
	if len(result.RejectedFeatures) != 1 || result.RejectedFeatures[0] != "p2p.quic" {
		t.Fatalf("unexpected rejected features: %+v", result.RejectedFeatures)
	}
}

func TestBuildAuthNegotiationResult_P2PRequestedDegradedWhenUnsupported(t *testing.T) {
	result := buildAuthNegotiationResult(uint16(fbMsg.ProtocolMajorCURRENT), 0, nil, []string{"p2p.quic"}, supportedAuthFeatures(true, true, true, true, true, false))
	if result.CompatibilityLevel != fbMsg.CompatibilityLevelCOMPAT_DEGRADED {
		t.Fatalf("expected degraded level, got=%v", result.CompatibilityLevel)
	}
	if result.ReasonCode != fbMsg.CompatibilityReasonCodeOK_DEGRADED_REQUESTED_FEATURE_REJECTED {
		t.Fatalf("unexpected reason code, got=%v", result.ReasonCode)
	}
	if len(result.RejectedFeatures) != 1 || result.RejectedFeatures[0] != "p2p.quic" {
		t.Fatalf("unexpected rejected features: %+v", result.RejectedFeatures)
	}
}

func TestBuildAuthNegotiationResult_P2PRequestedAcceptedWhenSupported(t *testing.T) {
	result := buildAuthNegotiationResult(uint16(fbMsg.ProtocolMajorCURRENT), 0, nil, []string{"p2p.quic"}, supportedAuthFeatures(true, true, true, true, true, true))
	if result.CompatibilityLevel != fbMsg.CompatibilityLevelCOMPAT_FULL {
		t.Fatalf("expected full level, got=%v", result.CompatibilityLevel)
	}
	if result.ReasonCode != fbMsg.CompatibilityReasonCodeOK_FULL {
		t.Fatalf("unexpected reason code, got=%v", result.ReasonCode)
	}
	if len(result.AcceptedFeatures) != 1 || result.AcceptedFeatures[0] != "p2p.quic" {
		t.Fatalf("unexpected accepted features: %+v", result.AcceptedFeatures)
	}
}

func TestSupportedAuthFeatures_P2PQUICFlag(t *testing.T) {
	withoutP2P := supportedAuthFeatures(true, true, true, true, true, false)
	if _, ok := withoutP2P["p2p.quic"]; ok {
		t.Fatalf("expected p2p.quic excluded when p2p support disabled")
	}
	if _, ok := withoutP2P["tcp"]; !ok {
		t.Fatalf("expected base feature tcp present")
	}

	withP2P := supportedAuthFeatures(true, true, true, true, true, true)
	if _, ok := withP2P["p2p.quic"]; !ok {
		t.Fatalf("expected p2p.quic included when p2p support enabled")
	}
}

func TestSupportedAuthFeatures_DynamicProtocolSet(t *testing.T) {
	supported := supportedAuthFeatures(false, false, true, false, false, false)
	if _, ok := supported["tcp"]; !ok {
		t.Fatalf("expected tcp supported")
	}
	if _, ok := supported["udp"]; ok {
		t.Fatalf("expected udp unsupported")
	}
	if _, ok := supported["http"]; ok {
		t.Fatalf("expected http unsupported")
	}
	if _, ok := supported["wireguard"]; ok {
		t.Fatalf("expected wireguard unsupported")
	}
	if _, ok := supported["relay.fallback"]; !ok {
		t.Fatalf("expected relay.fallback always supported")
	}
}
