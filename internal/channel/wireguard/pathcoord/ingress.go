package pathcoord

import (
	"fmt"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
)

const MaxControlBytes = 64 * 1024
const MaxActualAllowedIPs = 4096

// ControlMessage is decoded only after checking the exact header/union pairing,
// byte/vector/string bounds and required nested tables. It is still untrusted:
// Registry and Coordinator perform authentication and phase/evidence validation.
type ControlMessage struct {
	Runtime *fb.WGPathRuntimeReportT
	Report  *fb.WGPathReportT
	Request *fb.WGPathRequestT
}

func bounded(value []byte, maximum int) error {
	if len(value) > maximum {
		return fmt.Errorf("WG control string exceeds bound")
	}
	return nil
}

func checkMode(setting *fb.WGPathModeSetting) error {
	if setting == nil {
		return nil
	}
	for _, value := range [][]byte{setting.DecisionId(), setting.RequestId(), setting.RequestedByMemberId()} {
		if err := bounded(value, 256); err != nil {
			return err
		}
	}
	if setting.Mode() > fb.WGPathTypeRELAY || setting.Reason() > fb.WGPathModeReasonCONFLICT_RECOVERY {
		return fmt.Errorf("unknown WG mode/reason")
	}
	return nil
}

func checkVersion(v *fb.WGPathVersion) error {
	if v == nil {
		return fmt.Errorf("missing WG path version")
	}
	for _, value := range [][]byte{v.NetworkId(), v.MemberAId(), v.MemberBId(), v.CoordinatorEdgeId(), v.AuthorityEpoch(), v.AttemptId()} {
		if err := bounded(value, 256); err != nil {
			return err
		}
	}
	return nil
}

// DecodeControl recovers malformed FlatBuffer offsets locally, without hiding
// panics from handler/registry/owner execution. Bounds precede object UnPack so
// hostile vector lengths cannot cause allocation amplification.
func DecodeControl(message *fb.Message) (decoded ControlMessage, err error) {
	defer func() {
		if recover() != nil {
			decoded, err = ControlMessage{}, fmt.Errorf("malformed WG control buffer")
		}
	}()
	if message == nil || len(message.Table().Bytes) > MaxControlBytes {
		return ControlMessage{}, fmt.Errorf("missing/oversized WG control message")
	}
	header := message.Header(nil)
	if header == nil {
		return ControlMessage{}, fmt.Errorf("missing WG control header")
	}
	var body flatbuffers.Table
	if !message.Body(&body) {
		return ControlMessage{}, fmt.Errorf("missing WG control body")
	}
	switch header.Type() {
	case fb.MessageTypeWG_PATH_RUNTIME:
		if message.BodyType() != fb.MessageBodyWGPathRuntimeReport {
			return ControlMessage{}, fmt.Errorf("WG runtime union mismatch")
		}
		var runtime fb.WGPathRuntimeReport
		runtime.Init(body.Bytes, body.Pos)
		member := runtime.Member(nil)
		if member == nil || member.CandidatesLength() > MaxCandidates {
			return ControlMessage{}, fmt.Errorf("missing WG runtime member or excessive candidates")
		}
		for _, value := range [][]byte{runtime.NetworkId(), runtime.AuthorityEpoch(), member.MemberId(), member.DeviceId(), member.PublicKey(),
			member.AssignedIp(), member.MembershipGeneration(), member.RuntimeGeneration(), member.NetworkEnvironment()} {
			if err := bounded(value, 256); err != nil {
				return ControlMessage{}, err
			}
		}
		for i := 0; i < member.CandidatesLength(); i++ {
			var candidate fb.WGPathCandidate
			if !member.Candidates(&candidate, i) {
				return ControlMessage{}, fmt.Errorf("missing WG candidate")
			}
			if err := bounded(candidate.Endpoint(), 64); err != nil {
				return ControlMessage{}, err
			}
		}
		return ControlMessage{Runtime: runtime.UnPack()}, nil
	case fb.MessageTypeWG_PATH_REPORT:
		if message.BodyType() != fb.MessageBodyWGPathReport {
			return ControlMessage{}, fmt.Errorf("WG report union mismatch")
		}
		var report fb.WGPathReport
		report.Init(body.Bytes, body.Pos)
		if err := checkMode(report.SavedMode(nil)); err != nil {
			return ControlMessage{}, err
		}
		if err := checkVersion(report.Version(nil)); err != nil {
			return ControlMessage{}, err
		}
		if version := report.AppliedVersion(nil); version != nil {
			if err := checkVersion(version); err != nil {
				return ControlMessage{}, err
			}
		}
		if report.ActualAllowedIpsLength() > MaxActualAllowedIPs {
			return ControlMessage{}, fmt.Errorf("excessive WG actual allowed IPs")
		}
		for i := 0; i < report.ActualAllowedIpsLength(); i++ {
			if err := bounded(report.ActualAllowedIps(i), 64); err != nil {
				return ControlMessage{}, err
			}
		}
		for _, value := range [][]byte{report.MemberId(), report.RuntimeGeneration(), report.NetworkEnvironment(),
			report.ActualOwnerPublicKey(), report.ActualEndpoint(), report.CommandId(), report.PreparedPeerPublicKey(), report.PreparedEndpoint()} {
			if err := bounded(value, 256); err != nil {
				return ControlMessage{}, err
			}
		}
		if err := bounded(report.ErrorMessage(), 1024); err != nil {
			return ControlMessage{}, err
		}
		if business := report.Business(nil); business != nil && business.VerificationNonceLength() > 16 {
			return ControlMessage{}, fmt.Errorf("excessive WG business nonce")
		}
		if report.LastConfirmedPlan(nil) != nil {
			return ControlMessage{}, fmt.Errorf("WG client report cannot carry legacy reconciliation history")
		}
		return ControlMessage{Report: report.UnPack()}, nil
	case fb.MessageTypeWG_PATH_REQUEST:
		if message.BodyType() != fb.MessageBodyWGPathRequest {
			return ControlMessage{}, fmt.Errorf("WG request union mismatch")
		}
		var request fb.WGPathRequest
		request.Init(body.Bytes, body.Pos)
		if err := bounded(request.RequestId(), 256); err != nil {
			return ControlMessage{}, err
		}
		if err := bounded(request.ObservedAuthorityEpoch(), 256); err != nil {
			return ControlMessage{}, err
		}
		if err := bounded(request.ObservedCommandId(), 256); err != nil {
			return ControlMessage{}, err
		}
		if err := checkMode(request.LocalMode(nil)); err != nil {
			return ControlMessage{}, err
		}
		if err := bounded(request.NetworkId(), 256); err != nil {
			return ControlMessage{}, err
		}
		if err := bounded(request.PeerMemberId(), 256); err != nil {
			return ControlMessage{}, err
		}
		decoded := request.UnPack()
		if err := ValidateRequest(decoded); err != nil {
			return ControlMessage{}, err
		}
		return ControlMessage{Request: decoded}, nil
	default:
		return ControlMessage{}, fmt.Errorf("WG path command is not client ingress")
	}
}
