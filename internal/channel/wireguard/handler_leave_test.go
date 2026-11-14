package wireguard

import (
	"testing"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
)

type leaveTestCoordinator struct {
	HandlerCoordinator
	self             *NetworkMember
	overview         *NetworkOverview
	temporaryCalls   int
	permanentCalls   int
	removedCalls     int
	relayNoticeCalls int
}

type leaveTestPusher struct{}

func (leaveTestPusher) PushToClient(string, []byte) error   { return nil }
func (leaveTestPusher) AsyncPushToClients([]string, []byte) {}

func (c *leaveTestCoordinator) GetClientMember(string, string) (*NetworkMember, error) {
	return c.self, nil
}
func (c *leaveTestCoordinator) GetNetworkOverview(string) (*NetworkOverview, error) {
	return c.overview, nil
}
func (c *leaveTestCoordinator) GetNetwork(string) (*Network, error) {
	return c.overview.Network, nil
}
func (c *leaveTestCoordinator) SetMemberDisconnected(string) error {
	c.temporaryCalls++
	return nil
}
func (c *leaveTestCoordinator) SetMemberOffline(string) error {
	c.permanentCalls++
	return nil
}
func (c *leaveTestCoordinator) RemoveMember(string) error {
	c.removedCalls++
	return nil
}
func (c *leaveTestCoordinator) NotifyRelayPeerLeft(string, string) {
	c.relayNoticeCalls++
}

func buildLeaveRequest(t *testing.T, memberID string, temporary bool) *fb.Message {
	t.Helper()
	builder := flatbuffers.NewBuilder(256)
	message := (&fb.MessageT{
		Header: &fb.MessageHeaderT{Type: fb.MessageTypeWG_LEAVE_NETWORK, Seq: 9},
		Body: &fb.MessageBodyT{
			Type: fb.MessageBodyWGLeaveNetworkRequest,
			Value: &fb.WGLeaveNetworkRequestT{
				NetworkId: "net",
				MemberId:  memberID,
				Temporary: temporary,
			},
		},
	}).Pack(builder)
	builder.Finish(message)
	return fb.GetRootAsMessage(builder.FinishedBytes(), 0)
}

func TestHandleLeaveNetworkTemporaryOnlyDisconnectsSelf(t *testing.T) {
	member := &NetworkMember{ID: "member-a", ClientID: "device-a", PublicKey: "key-a", Status: MemberStatusActive}
	coord := &leaveTestCoordinator{
		self: member,
		overview: &NetworkOverview{
			Network: &Network{ID: "net", OwnerUserID: "user-a"},
			Members: []*NetworkMember{member},
		},
	}
	handler := NewWireGuardHandler(coord, leaveTestPusher{}, nil, "edge", nil)
	ctx := HandlerSession{Conn: &pathReceiptConn{}, UserID: "user-a", DeviceID: "device-a"}

	if err := handler.HandleLeaveNetwork(ctx, buildLeaveRequest(t, "", true)); err != nil {
		t.Fatalf("temporary leave failed: %v", err)
	}
	if coord.temporaryCalls != 1 || coord.permanentCalls != 0 || coord.removedCalls != 0 || coord.relayNoticeCalls != 0 {
		t.Fatalf("temporary leave side effects: temporary=%d permanent=%d removed=%d relay=%d",
			coord.temporaryCalls, coord.permanentCalls, coord.removedCalls, coord.relayNoticeCalls)
	}

	if err := handler.HandleLeaveNetwork(ctx, buildLeaveRequest(t, "", false)); err != nil {
		t.Fatalf("explicit leave failed: %v", err)
	}
	if coord.temporaryCalls != 1 || coord.permanentCalls != 1 || coord.removedCalls != 0 || coord.relayNoticeCalls != 1 {
		t.Fatalf("explicit leave side effects: temporary=%d permanent=%d removed=%d relay=%d",
			coord.temporaryCalls, coord.permanentCalls, coord.removedCalls, coord.relayNoticeCalls)
	}
}

func TestHandleLeaveNetworkTemporaryCannotTargetAnotherMember(t *testing.T) {
	self := &NetworkMember{ID: "member-a", ClientID: "device-a", PublicKey: "key-a", Status: MemberStatusOnline}
	other := &NetworkMember{ID: "member-b", ClientID: "device-b", PublicKey: "key-b", Status: MemberStatusOnline}
	coord := &leaveTestCoordinator{
		self: self,
		overview: &NetworkOverview{
			Network: &Network{ID: "net", OwnerUserID: "user-a"},
			Members: []*NetworkMember{self, other},
		},
	}
	handler := NewWireGuardHandler(coord, nil, nil, "edge", nil)
	ctx := HandlerSession{Conn: &pathReceiptConn{}, UserID: "user-a", DeviceID: "device-a"}

	if err := handler.HandleLeaveNetwork(ctx, buildLeaveRequest(t, "member-b", true)); err != nil {
		t.Fatalf("handler transport error: %v", err)
	}
	if coord.temporaryCalls != 0 || coord.permanentCalls != 0 || coord.removedCalls != 0 {
		t.Fatalf("temporary request changed another member: temporary=%d permanent=%d removed=%d",
			coord.temporaryCalls, coord.permanentCalls, coord.removedCalls)
	}
}
