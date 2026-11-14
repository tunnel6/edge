package wireguard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/internal/channel/wireguard/pathcoord"
)

type pathReceiptConn struct {
	net.Conn
	written bytes.Buffer
}

func (c *pathReceiptConn) Write(data []byte) (int, error) { return c.written.Write(data) }

type pathReceiptCoordinator struct{ HandlerCoordinator }

func (*pathReceiptCoordinator) GetNetworkOverview(network string) (*NetworkOverview, error) {
	return &NetworkOverview{Network: &Network{ID: network, OwnerUserID: "user", CIDR: "10.24.0.0/24"}}, nil
}

type pathReceiptReceiver struct{ err error }

func (r pathReceiptReceiver) HandlePathControl(types.SessionIdentity, pathcoord.ControlMessage) error {
	return r.err
}

func TestPathProposalReceiptKeepsRequestSequenceAndRejectsWithoutSuccess(t *testing.T) {
	rejected := errors.New("WG path negotiation capacity reached")
	for _, tc := range []struct {
		name string
		seq  uint32
		err  error
	}{
		{"accepted", 42, nil},
		{"rejected", 43, rejected},
		{"legacy_no_receipt", 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &pathReceiptConn{}
			h := NewWireGuardHandler(&pathReceiptCoordinator{}, nil, nil, "edge", nil)
			if err := h.AttachPathControlReceiver(pathReceiptReceiver{tc.err}); err != nil {
				t.Fatal(err)
			}
			builder := flatbuffers.NewBuilder(512)
			message := (&fb.MessageT{
				Header: &fb.MessageHeaderT{Type: fb.MessageTypeWG_PATH_REQUEST, Seq: tc.seq},
				Body: &fb.MessageBodyT{Type: fb.MessageBodyWGPathRequest, Value: &fb.WGPathRequestT{
					NetworkId: "net", PeerMemberId: "b", Kind: fb.WGPathRequestKindCHANGE_MODE,
					RequestedPath: fb.WGPathTypeRELAY, RequestId: "click", ObservedAuthorityEpoch: "epoch",
				}},
			}).Pack(builder)
			builder.Finish(message)
			err := h.HandlePathControl(HandlerSession{Conn: conn, UserID: "user", DeviceID: "a", SessionID: "session-a"}, fb.GetRootAsMessage(builder.FinishedBytes(), 0))
			if !errors.Is(err, tc.err) {
				t.Fatalf("HandlePathControl = %v, want %v", err, tc.err)
			}
			if tc.err != nil || tc.seq == 0 {
				if conn.written.Len() != 0 {
					t.Fatal("rejected or legacy proposal received a success receipt")
				}
				return
			}
			frame := conn.written.Bytes()
			if len(frame) < 4 || int(binary.BigEndian.Uint32(frame[:4])) != len(frame)-4 {
				t.Fatal("invalid receipt framing")
			}
			response := fb.GetRootAsMessage(frame[4:], 0)
			if response.Header(nil).Seq() != tc.seq || response.Header(nil).Type() != fb.MessageTypeWG_NETWORK_RUNTIME_RESPONSE {
				t.Fatal("receipt type/sequence does not match proposal")
			}
			body := flatbuffers.Table{}
			if !response.Body(&body) {
				t.Fatal("missing receipt body")
			}
			var receipt fb.WGNetworkRuntimeResponse
			receipt.Init(body.Bytes, body.Pos)
			if !receipt.Success() || receipt.Snapshot(nil) == nil || string(receipt.Snapshot(nil).Network(nil).NetworkId()) != "net" {
				t.Fatal("receipt must contain the accepted proposal's network snapshot")
			}
		})
	}
}
