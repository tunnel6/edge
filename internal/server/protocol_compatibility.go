package server

import (
	"fmt"
	"net"

	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/pkg/config"
	logger "icool.io/yat/edge/pkg/log"
)

// AUTH IDs and its legacy field defaults stay stable so protocol 1 clients can
// receive a useful rejection before any protocol 2 business ID is dispatched.
func negotiateSessionProtocol(protocol *Protocol, conn net.Conn, req *fb.AuthRequest, supported map[string]struct{}) (AuthNegotiationResult, bool) {
	required := make([]string, 0, req.RequiredFeaturesLength())
	for i := 0; i < req.RequiredFeaturesLength(); i++ {
		required = append(required, string(req.RequiredFeatures(i)))
	}
	requested := make([]string, 0, req.RequestedFeaturesLength())
	for i := 0; i < req.RequestedFeaturesLength(); i++ {
		requested = append(requested, string(req.RequestedFeatures(i)))
	}
	result := buildAuthNegotiationResult(req.ProtocolMajor(), req.ProtocolMinor(), required, requested, supported)
	if result.CompatibilityLevel != fb.CompatibilityLevelCOMPAT_INCOMPATIBLE {
		return result, true
	}
	var message string
	if result.ReasonCode == fb.CompatibilityReasonCodeINCOMPATIBLE_PROTOCOL_MAJOR_MISMATCH {
		message = fmt.Sprintf(
			"Client/Edge wire protocol mismatch: client %s protocol %d.%d, Edge %s requires protocol %d.%d. Use client and Edge builds with matching wire protocols.",
			string(req.ClientVersion()), req.ProtocolMajor(), req.ProtocolMinor(), config.Version, result.NegotiatedProtocolMajor, result.NegotiatedProtocolMinor,
		)
	} else {
		message = fmt.Sprintf("Required capabilities unavailable on Edge %s: %v; reason_code=%d", config.Version, result.RejectedFeatures, result.ReasonCode)
	}
	logger.Warnf("[Auth] %s", message)
	_ = protocol.SendAuthResponse(conn, false, "", message, uint32(fb.ErrorCodeAUTH_FAILED), &result)
	return result, false
}
