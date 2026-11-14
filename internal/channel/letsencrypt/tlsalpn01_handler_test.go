package letsencrypt

import (
	"crypto/tls"
	"testing"
)

func TestTLSALPN01HandlerDeleteDomain(t *testing.T) {
	handler := NewTLSALPN01Handler()
	if err := handler.Set("api.example.com", "token-a", "ka-a"); err != nil {
		t.Fatalf("Set token-a returned error: %v", err)
	}
	if err := handler.Set("api.example.com", "token-b", "ka-b"); err != nil {
		t.Fatalf("Set token-b returned error: %v", err)
	}

	hello := &tls.ClientHelloInfo{
		ServerName:      "api.example.com",
		SupportedProtos: []string{TLSALPN01Protocol},
	}
	if _, ok := handler.Resolve(hello); !ok {
		t.Fatal("expected tls-alpn challenge cert before DeleteDomain")
	}

	handler.DeleteDomain("api.example.com")

	if _, ok := handler.Resolve(hello); ok {
		t.Fatal("tls-alpn challenge cert should be cleaned up by DeleteDomain")
	}
}
