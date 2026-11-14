package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/pkg/config"
)

func TestManagementLimitsPersistAndOverrideDeployment(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Tunnel.Limits = config.TunnelLimits{MaxPerSession: 10, MaxTotal: 50}
	server := &Server{config: cfg, opts: defaultServerOptions()}
	for _, limits := range []string{
		`{"tunnel":{"limits":{"max_per_session":3,"max_total":7}}}`,
		`{"tunnel":{"limits":{"max_per_session":0,"max_total":0}}}`,
	} {
		saved, restart, err := server.updateManagementConfig(limits)
		if err != nil {
			t.Fatal(err)
		}
		if restart {
			t.Fatal("limit changes must apply without a restart")
		}
		if cfg.GetTunnelMaxPerSession() != int(*saved.Tunnel.Limits.MaxPerSession) || cfg.GetTunnelMaxTotal() != int(*saved.Tunnel.Limits.MaxTotal) {
			t.Fatal("runtime enforcement does not use the saved limits")
		}
		// A fresh process has old deployment/CLI values, then reads local overrides.
		restarted := config.DefaultConfig()
		restarted.Tunnel.Limits = config.TunnelLimits{MaxPerSession: 99, MaxTotal: 999}
		persisted, err := config.LoadManagementConfig(cfg.GetDataDir())
		if err != nil {
			t.Fatal(err)
		}
		persisted.ApplyAtStartup(restarted)
		if restarted.GetTunnelMaxPerSession() != cfg.GetTunnelMaxPerSession() || restarted.GetTunnelMaxTotal() != cfg.GetTunnelMaxTotal() {
			t.Fatal("old deployment values replaced managed limits at restart")
		}
	}
	if _, restart, err := server.updateManagementConfig(`{"channel":{"http":{"port":18081,"https_port":0},"custom_domain":""}}`); err != nil || !restart {
		t.Fatalf("listener changes need an explicit restart result: restart=%v err=%v", restart, err)
	}
	if cfg.Proxy.HTTP.Port == 18081 {
		t.Fatal("listener port was reported applied without rebinding")
	}
	persisted, err := config.LoadManagementConfig(cfg.GetDataDir())
	if err != nil {
		t.Fatal(err)
	}
	restarted := config.DefaultConfig()
	persisted.ApplyAtStartup(restarted)
	opts := defaultServerOptions()
	WithRegistryHTTPPort(9090)(&opts) // old deployment option
	applyManagementOptions(persisted, restarted, &opts)
	if restarted.Proxy.HTTP.Port != 18081 || restarted.Proxy.HTTP.HTTPSPort != 0 || *opts.registryHTTPPort != 18081 {
		t.Fatal("saved ports did not override deployment config and constructor options")
	}
	read, restart, err := server.updateManagementConfig("")
	if err != nil || !restart || *read.Channel.HTTP.Port != 18081 {
		t.Fatal("read-back lost pending saved configuration", err)
	}
}

func TestManagementRejectsInvalidConfigAndPersistenceFailure(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Tunnel.Limits.MaxTotal = 12
	server := &Server{config: cfg}
	for _, invalid := range []string{
		`{"tunnel":{"limits":{"max_total":-1}}}`,
		`{"tunnel":{"limits":{"max_total":1.5}}}`,
		`{"tunnel":{"limits":{"max_total":4294967296}}}`,
		`{"channel":{"http":{"port":70000}}}`,
		`{"channel":{"tcp":{"enable":true,"port_min":3000,"port_max":2000}}}`,
		`{"controller":{"address":"attacker:1234"}}`,
		`{"node":{"owner_user_id":"attacker"}}`,
		`null`, `{} {}`,
	} {
		if _, _, err := server.updateManagementConfig(invalid); err == nil {
			t.Fatalf("invalid update succeeded: %s", invalid)
		}
	}
	if cfg.GetTunnelMaxTotal() != 12 {
		t.Fatal("validation failure changed runtime limits")
	}
	file := filepath.Join(cfg.GetDataDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.DataDir = file
	if _, _, err := server.updateManagementConfig(`{"tunnel":{"limits":{"max_total":4}}}`); err == nil {
		t.Fatal("failed persistence was acknowledged as success")
	}
	if cfg.GetTunnelMaxTotal() != 12 {
		t.Fatal("failed persistence changed runtime limits")
	}
}

func TestManagementReadReflectsConstructorOptions(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	opts := defaultServerOptions()
	WithRegistryHTTPPort(18081)(&opts)
	WithRegistryHTTPSPort(0)(&opts)
	WithTCPPortRange(21000, 22000)(&opts)
	WithP2PEnabled(false)(&opts)
	server := &Server{config: cfg, opts: opts}
	saved, restart, err := server.updateManagementConfig(`{"tunnel":{"limits":{"max_total":1}}}`)
	if err != nil || restart || *saved.Channel.HTTP.Port != 18081 || *saved.Channel.HTTP.HTTPSPort != 0 || *saved.Channel.TCP.PortMin != 21000 || *saved.Server.Capabilities.P2P {
		t.Fatalf("saving a limit drifted constructor options: restart=%v err=%v", restart, err)
	}
}

func TestManagementWireOwnerAuthorizationAndAcknowledgment(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	server := &Server{config: cfg, opts: defaultServerOptions()}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		user    string
		role    string
		scopes  []string
		success bool
	}{
		{"same-user", "device", nil, false}, {"same-user", "owner", []string{"network:restricted"}, false}, {"same-user", "owner", nil, true},
	} {
		a, b := net.Pipe()
		serverConn := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13})
		clientConn := tls.Client(b, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) // In-memory fixture only.
		_ = a.SetDeadline(time.Now().Add(3 * time.Second))
		_ = b.SetDeadline(time.Now().Add(3 * time.Second))
		done := make(chan error, 1)
		go func() {
			protocol := NewProtocol()
			message, err := protocol.ReadMessage(serverConn)
			if err == nil {
				err = server.handleMessage(&Session{ID: "session", UserID: test.user, Role: test.role, ScopeClaims: test.scopes, Conn: serverConn, Protocol: protocol}, message)
			}
			done <- err
		}()
		builder := flatbuffers.NewBuilder(256)
		message := &fb.MessageT{Header: &fb.MessageHeaderT{Type: fb.MessageTypeEDGE_CONFIG_REQUEST, Seq: 42},
			Body: &fb.MessageBodyT{Type: fb.MessageBodyEdgeConfigRequest, Value: &fb.EdgeConfigRequestT{ConfigJson: `{"tunnel":{"limits":{"max_total":5}}}`}}}
		builder.Finish(message.Pack(builder))
		protocol := NewProtocol()
		if err := protocol.WriteMessage(clientConn, builder.FinishedBytes()); err != nil {
			t.Fatal(err)
		}
		response, err := protocol.ReadMessage(clientConn)
		if err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if response.Header(nil).Type() != fb.MessageTypeEDGE_CONFIG_RESPONSE || response.Header(nil).Seq() != 42 {
			t.Fatal("response lost type/sequence correlation")
		}
		var table flatbuffers.Table
		response.Body(&table)
		body := fb.EdgeConfigResponse{}
		body.Init(table.Bytes, table.Pos)
		if body.Success() != test.success {
			t.Fatalf("user=%s scopes=%v success=%v error=%s", test.user, test.scopes, body.Success(), body.ErrorMessage())
		}
		if test.success {
			var saved config.ManagementConfig
			if err := json.Unmarshal(body.ConfigJson(), &saved); err != nil {
				t.Fatal(err)
			}
			persisted, err := config.LoadManagementConfig(cfg.GetDataDir())
			if err != nil || *persisted.Tunnel.Limits.MaxTotal != 5 || cfg.GetTunnelMaxTotal() != 5 {
				t.Fatal("success preceded persist/apply", err)
			}
		} else if _, err := os.Stat(filepath.Join(cfg.GetDataDir(), config.ManagementConfigFile)); !os.IsNotExist(err) {
			t.Fatal("non-owner wrote configuration")
		}
		_ = a.Close()
		_ = b.Close()
	}
}
