package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/upstream/certmgr"
	"icool.io/yat/edge/pkg/config"
)

func TestProtocolV2RejectsOldDesktopBeforeBusinessSession(t *testing.T) {
	for _, legacy := range []string{"missing protocol field", "explicit protocol 1"} {
		t.Run(legacy, func(t *testing.T) {
			builder := flatbuffers.NewBuilder(256)
			version := builder.CreateString("1.3.0")
			fb.AuthRequestStart(builder)
			fb.AuthRequestAddClientVersion(builder, version)
			if legacy == "explicit protocol 1" {
				// Force the old value onto the wire instead of omitting a default.
				builder.PrependUint16Slot(5, 1, 0)
			}
			req := fb.AuthRequestEnd(builder)
			fb.MessageHeaderStart(builder)
			fb.MessageHeaderAddType(builder, fb.MessageTypeAUTH_REQUEST)
			header := fb.MessageHeaderEnd(builder)
			fb.MessageStart(builder)
			fb.MessageAddHeader(builder, header)
			fb.MessageAddBodyType(builder, fb.MessageBodyAuthRequest)
			fb.MessageAddBody(builder, req)
			builder.Finish(fb.MessageEnd(builder))
			requestMessage := fb.GetRootAsMessage(builder.FinishedBytes(), 0)
			var requestTable flatbuffers.Table
			requestMessage.Body(&requestTable)
			request := &fb.AuthRequest{}
			request.Init(requestTable.Bytes, requestTable.Pos)
			if request.ProtocolMajor() != 1 {
				t.Fatal("missing or legacy field was reinterpreted as protocol 2")
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			_ = a.SetDeadline(time.Now().Add(2 * time.Second))
			_ = b.SetDeadline(time.Now().Add(2 * time.Second))
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device_legacy"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
			authDER, authErr := asn1.Marshal(certmgr.EdgeAuthorization{EdgeID: "edge-test", Role: certmgr.RoleDevice})
			if authErr != nil {
				t.Fatal(authErr)
			}
			template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}, Value: authDER})
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
			serverConn := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequestClientCert})
			clientConn := tls.Client(b, &tls.Config{Certificates: []tls.Certificate{pair}, InsecureSkipVerify: true}) // In-memory fixture only.
			cfg := &config.Config{}
			cfg.Node.Type = "public"
			cfg.Node.ID = "edge-test"
			server := &Server{config: cfg, sessions: NewSessionManager(8)}
			server.wg.Add(1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				server.handleConnection(serverConn)
			}()
			if err := NewProtocol().WriteMessage(clientConn, builder.FinishedBytes()); err != nil {
				t.Fatal(err)
			}
			message, err := NewProtocol().ReadMessage(clientConn)
			if err != nil {
				t.Fatal(err)
			}
			if message.Header(nil).Type() != fb.MessageTypeAUTH_RESPONSE || message.BodyType() != fb.MessageBodyAuthResponse {
				t.Fatal("rejection changed the stable Auth envelope")
			}
			var table flatbuffers.Table
			message.Body(&table)
			var response fb.AuthResponse
			response.Init(table.Bytes, table.Pos)
			if response.Success() || len(response.SessionId()) != 0 || server.sessions.Count() != 0 {
				t.Fatal("legacy desktop was admitted to a business session")
			}
			if response.NegotiatedProtocolMajor() != 2 || response.ReasonCode() != fb.CompatibilityReasonCodeINCOMPATIBLE_PROTOCOL_MAJOR_MISMATCH {
				t.Fatalf("incorrect compatibility result: %d / %s", response.NegotiatedProtocolMajor(), response.ReasonCode())
			}
			if string(response.ServerVersion()) != config.Version || !strings.Contains(string(response.ErrorMessage()), "requires protocol 2.0") {
				t.Fatal("missing actual Edge version or actionable upgrade message")
			}
			_ = clientConn.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("rejected client connection was not closed")
			}
		})
	}
}

func TestProtocolV2AcceptsMatchingDesktopWithoutLegacyIDTranslation(t *testing.T) {
	builder := flatbuffers.NewBuilder(256)
	root := (&fb.AuthRequestT{ClientVersion: "1.3.0", ProtocolMajor: uint16(fb.ProtocolMajorCURRENT), ProtocolMinor: uint16(fb.ProtocolMinorCURRENT)}).Pack(builder)
	builder.Finish(root)
	result, accepted := negotiateSessionProtocol(nil, nil, fb.GetRootAsAuthRequest(builder.FinishedBytes(), 0), nil)
	if !accepted || result.NegotiatedProtocolMajor != uint16(fb.ProtocolMajorCURRENT) || result.NegotiatedProtocolMinor != uint16(fb.ProtocolMinorCURRENT) || result.CompatibilityLevel != fb.CompatibilityLevelCOMPAT_FULL {
		t.Fatalf("matching desktop rejected: %+v", result)
	}
	if fb.MessageTypeEDGE_DOMAIN_CERTIFICATE_REQUEST != 0x6009 || fb.MessageTypeTUNNEL_SYNC_REQUEST != 0x6100 || fb.MessageTypeTUNNEL_LEAVE_RESPONSE != 0x6110 {
		t.Fatal("Edge and Tunnel message ranges overlap or drifted")
	}
	if fb.MessageBodyEdgeDomainCertificateRequest != 82 || fb.MessageBodyEdgeDomainCertificateResponse != 83 {
		t.Fatal("union body tags changed while reorganizing header message IDs")
	}
}
