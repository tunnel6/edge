package wireguard

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/internal/channel/wireguard/pathcoord"
)

type runtimeBootstrapControls map[string]types.SessionIdentity

func (c runtimeBootstrapControls) CurrentClientSession(device string) (types.SessionIdentity, bool) {
	identity, ok := c[device]
	return identity, ok
}

func TestRuntimeReadPreservesCoordinationBootstrapFailures(t *testing.T) {
	for _, scenario := range []string{"current", "ordinary_reader", "retired_session", "missing_capability", "left", "removed", "removed_old_container"} {
		t.Run(scenario, func(t *testing.T) {
			mm, _ := newPathMembershipFixture(t)
			coordinator := &MeshCoordinator{NetworkManager: mm.networkManager, MemberManager: mm}
			// A device-only certificate is canonicalized by the server to a
			// device owner user ID. Network read access still comes from membership.
			identity := types.SessionIdentity{UserID: "device:device-a", DeviceID: "device-a", SessionID: "session-a",
				Capabilities: []string{pathcoord.Capability}, ScopeClaims: []string{"network:net"}}
			controls := runtimeBootstrapControls{"device-a": identity}
			owner, err := pathcoord.NewOwner("edge", mm, controls, pathcoord.OwnerConfig{
				Budgets:  pathcoord.Budgets{Prepare: time.Second, Apply: time.Second},
				Registry: pathcoord.RegistryLimits{Members: 8}, MaxPairs: 8, ControlBurst: 8, TickInterval: time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			h := NewWireGuardHandler(coordinator, nil, nil, "edge", nil)
			if err := h.AttachPathControlReceiver(owner); err != nil {
				t.Fatal(err)
			}
			wantError := ""
			switch scenario {
			case "ordinary_reader":
				identity.Capabilities = []string{"wg"}
				controls[identity.DeviceID] = identity
			case "retired_session":
				current := identity
				current.SessionID = "replacement-session"
				controls[identity.DeviceID] = current
				wantError = "retired/different authenticated session"
			case "missing_capability":
				current := identity
				current.Capabilities = []string{"wg"}
				controls[identity.DeviceID] = current
				wantError = "does not advertise " + pathcoord.Capability
			case "left":
				if err := mm.SetMemberOffline("a"); err != nil {
					t.Fatal(err)
				}
				wantError = pathcoord.ErrMembershipRevoked.Error()
			case "removed":
				if err := mm.RemoveMember("a"); err != nil {
					t.Fatal(err)
				}
				wantError = "network not found: net"
			case "removed_old_container":
				// Recreated containers can reuse an endpoint while having distinct
				// authenticated identities and WG keys. Removing the old member
				// must preserve the new container's bootstrap authorization.
				for _, device := range []string{"device-a", "device-b"} {
					binding, err := mm.PathMember("net", device)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := mm.ApplyObservedEndpoint("net", binding.Member.PublicKey, "198.51.100.10:58020"); err != nil {
						t.Fatal(err)
					}
				}
				if err := mm.RemoveMember("b"); err != nil {
					t.Fatal(err)
				}
			}
			conn := &pathReceiptConn{}
			ctx := HandlerSession{Conn: conn, UserID: identity.UserID, DeviceID: identity.DeviceID, SessionID: identity.SessionID,
				Capabilities: identity.Capabilities, ScopeClaims: identity.ScopeClaims}
			if err := h.sendNetworkRuntimeResponse(ctx, "net", 42); err != nil {
				t.Fatal(err)
			}
			frame := conn.written.Bytes()
			if len(frame) < 4 || int(binary.BigEndian.Uint32(frame[:4])) != len(frame)-4 {
				t.Fatal("invalid response frame")
			}
			message := fb.GetRootAsMessage(frame[4:], 0)
			if message.Header(nil).Seq() != 42 || message.Header(nil).Type() != fb.MessageTypeWG_NETWORK_RUNTIME_RESPONSE {
				t.Fatal("runtime failure must retain the request type/sequence")
			}
			var table flatbuffers.Table
			if !message.Body(&table) {
				t.Fatal("missing runtime response")
			}
			var response fb.WGNetworkRuntimeResponse
			response.Init(table.Bytes, table.Pos)
			if wantError != "" {
				if response.Success() || response.Snapshot(nil) != nil || !strings.Contains(string(response.ErrorMessage()), wantError) {
					t.Fatalf("success=%v snapshot=%v error=%q, want explicit failure containing %q",
						response.Success(), response.Snapshot(nil) != nil, response.ErrorMessage(), wantError)
				}
				return
			}
			snapshot := response.Snapshot(nil)
			if !response.Success() || snapshot == nil ||
				string(snapshot.Network(nil).SelfMemberId()) != "a" {
				t.Fatalf("current scoped member needs an authenticated coordination snapshot: %s", response.ErrorMessage())
			}
			if (len(snapshot.PathAuthorityEpoch()) != 0) != (scenario != "ordinary_reader") {
				t.Fatalf("wrong coordination epoch for %s: %q", scenario, snapshot.PathAuthorityEpoch())
			}
		})
	}
}
