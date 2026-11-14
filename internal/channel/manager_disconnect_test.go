package channel

import (
	"reflect"
	"testing"

	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/wireguard"
)

type disconnectTestCoordinator struct {
	wireGuardCoordinator
	networks     []*wireguard.Network
	members      map[string][]*wireguard.NetworkMember
	disconnected []string
}

func (c *disconnectTestCoordinator) HandleDeviceDisconnect(deviceID string) error {
	c.disconnected = append(c.disconnected, deviceID)
	return nil
}
func (c *disconnectTestCoordinator) ListNetworks() []*wireguard.Network { return c.networks }
func (c *disconnectTestCoordinator) ListNetworkMembers(networkID string) []*wireguard.NetworkMember {
	return c.members[networkID]
}

type disconnectTestHandler struct {
	wireGuardHandler
	pushed []string
}

func (h *disconnectTestHandler) PushNetworkEvent(networkID string, _ fb.WGNetworkEventAction) error {
	h.pushed = append(h.pushed, networkID)
	return nil
}

func TestSessionDisconnectPushesFreshPresenceOnlyForJoinedNetworks(t *testing.T) {
	coordinator := &disconnectTestCoordinator{
		networks: []*wireguard.Network{{ID: "net-1"}, {ID: "net-2"}},
		members: map[string][]*wireguard.NetworkMember{
			"net-1": {{ID: "member-a", ClientID: "device-a"}},
			"net-2": {{ID: "member-b", ClientID: "device-b"}},
		},
	}
	handler := &disconnectTestHandler{}
	manager := &ChannelManager{wgCoordinator: coordinator, wgHandler: handler}

	manager.HandleSessionDisconnect("device-a")

	if !reflect.DeepEqual(coordinator.disconnected, []string{"device-a"}) {
		t.Fatalf("disconnect calls = %v, want [device-a]", coordinator.disconnected)
	}
	if !reflect.DeepEqual(handler.pushed, []string{"net-1"}) {
		t.Fatalf("presence pushes = %v, want [net-1]", handler.pushed)
	}
}
