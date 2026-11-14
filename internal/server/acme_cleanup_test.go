package server

import (
	"crypto/tls"
	"testing"

	"icool.io/yat/edge/internal/channel/letsencrypt"
)

func TestClearChallengeStateOnCertReady(t *testing.T) {
	httpHandler := letsencrypt.NewHTTP01Handler()
	if err := httpHandler.Set("example.com", "token-a", "ka-a"); err != nil {
		t.Fatalf("http Set example.com failed: %v", err)
	}
	if err := httpHandler.Set("other.com", "token-b", "ka-b"); err != nil {
		t.Fatalf("http Set other.com failed: %v", err)
	}

	tlsHandler := letsencrypt.NewTLSALPN01Handler()
	if err := tlsHandler.Set("example.com", "token-a", "ka-a"); err != nil {
		t.Fatalf("tls Set example.com failed: %v", err)
	}
	if err := tlsHandler.Set("other.com", "token-b", "ka-b"); err != nil {
		t.Fatalf("tls Set other.com failed: %v", err)
	}

	svc := &HTTPSCertService{
		activeDNS01: map[string]*ActiveDNS01Challenge{
			"_acme-challenge.example.com": {
				RecordName: "_acme-challenge.example.com",
				Domain:     "*.example.com",
			},
			"_acme-challenge.other.com": {
				RecordName: "_acme-challenge.other.com",
				Domain:     "other.com",
			},
		},
		http01Handler:    httpHandler,
		tlsALPN01Handler: tlsHandler,
	}

	svc.clearChallengeStateOnCertReady("*.example.com")

	if _, ok := svc.activeDNS01["_acme-challenge.example.com"]; ok {
		t.Fatal("dns-01 challenge for example.com should be cleared")
	}
	if _, ok := svc.activeDNS01["_acme-challenge.other.com"]; !ok {
		t.Fatal("dns-01 challenge for other.com should be kept")
	}

	if _, ok := httpHandler.Resolve("example.com", "token-a"); ok {
		t.Fatal("http-01 challenge for example.com should be cleared")
	}
	if _, ok := httpHandler.Resolve("other.com", "token-b"); !ok {
		t.Fatal("http-01 challenge for other.com should be kept")
	}

	exampleHello := &tls.ClientHelloInfo{
		ServerName:      "example.com",
		SupportedProtos: []string{letsencrypt.TLSALPN01Protocol},
	}
	if _, ok := tlsHandler.Resolve(exampleHello); ok {
		t.Fatal("tls-alpn-01 challenge for example.com should be cleared")
	}

	otherHello := &tls.ClientHelloInfo{
		ServerName:      "other.com",
		SupportedProtos: []string{letsencrypt.TLSALPN01Protocol},
	}
	if _, ok := tlsHandler.Resolve(otherHello); !ok {
		t.Fatal("tls-alpn-01 challenge for other.com should be kept")
	}
}
