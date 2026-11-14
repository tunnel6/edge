package server

import (
	"testing"

	flatbuffers "github.com/google/flatbuffers/go"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
)

func TestParseAuthRequestSafe_ValidPayload(t *testing.T) {
	builder := flatbuffers.NewBuilder(256)
	auth := (&fbMsg.AuthRequestT{
		UserId:        "user-1",
		DeviceId:      "device-1",
		ClientVersion: "v1.0.0-rc3",
		Capabilities:  []string{"http", "tcp"},
		ProtocolMajor: 1,
		ProtocolMinor: 0,
	}).Pack(builder)
	fbMsg.FinishAuthRequestBuffer(builder, auth)
	req := fbMsg.GetRootAsAuthRequest(builder.FinishedBytes(), 0)

	userID, caps, err := parseAuthRequestSafe(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID != "user-1" {
		t.Fatalf("unexpected userID: %q", userID)
	}
	if len(caps) != 2 || caps[0] != "http" || caps[1] != "tcp" {
		t.Fatalf("unexpected capabilities: %#v", caps)
	}
}

func TestParseAuthRequestSafe_LegacyLayoutPayload(t *testing.T) {
	builder := flatbuffers.NewBuilder(256)
	userID := builder.CreateString("legacy-user")
	deviceID := builder.CreateString("legacy-device")
	clientVersion := builder.CreateString("v1.0.0-rc3")
	capHTTP := builder.CreateString("http")
	capTCP := builder.CreateString("tcp")

	builder.StartVector(4, 2, 4)
	builder.PrependUOffsetT(capTCP)
	builder.PrependUOffsetT(capHTTP)
	capabilities := builder.EndVector(2)

	// Legacy layout (before hostname was inserted):
	// 0:user_id 1:device_id 2:client_version 3:capabilities
	builder.StartObject(8)
	builder.PrependUOffsetTSlot(0, userID, 0)
	builder.PrependUOffsetTSlot(1, deviceID, 0)
	builder.PrependUOffsetTSlot(2, clientVersion, 0)
	builder.PrependUOffsetTSlot(3, capabilities, 0)
	builder.PrependUint16Slot(4, 1, 1)
	builder.PrependUint16Slot(5, 0, 0)
	root := builder.EndObject()
	builder.Finish(root)

	req := fbMsg.GetRootAsAuthRequest(builder.FinishedBytes(), 0)
	parsedUser, caps, err := parseAuthRequestSafe(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsedUser != "legacy-user" {
		t.Fatalf("unexpected userID: %q", parsedUser)
	}
	if len(caps) != 2 || caps[0] != "http" || caps[1] != "tcp" {
		t.Fatalf("unexpected capabilities: %#v", caps)
	}
}

func TestParseAuthRequestSafe_NilRequest(t *testing.T) {
	_, _, err := parseAuthRequestSafe(nil)
	if err == nil {
		t.Fatal("expected error for nil auth request")
	}
}

func TestParseAuthRequestSafe_RecoversFromPanic(t *testing.T) {
	req := &fbMsg.AuthRequest{}
	_, _, err := parseAuthRequestSafe(req)
	if err == nil {
		t.Fatal("expected error when parsing malformed auth request")
	}
}
