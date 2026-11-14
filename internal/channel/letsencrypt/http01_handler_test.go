package letsencrypt

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTP01HandlerServeHTTP(t *testing.T) {
	handler := NewHTTP01Handler()
	if err := handler.Set("api.example.com", "token-a", "token-a.thumbprint"); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/token-a", nil)
	req.Host = "api.example.com:80"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: got=%d want=%d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); body != "token-a.thumbprint" {
		t.Fatalf("unexpected response body: got=%q", body)
	}
}

func TestHTTP01HandlerServeHTTPNotFound(t *testing.T) {
	handler := NewHTTP01Handler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/not-found", nil)
	req.Host = "api.example.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unexpected status code: got=%d want=%d", rec.Code, http.StatusNotFound)
	}
}

func TestHTTP01ChallengeCleanupOnFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	_ = listener.Close()

	handler := NewHTTP01Handler()
	challenge := NewHTTP01Challenge(listener, handler, nil, 20*time.Millisecond)
	startErr := challenge.Start(context.Background(), &ChallengeStartRequest{
		Domain:           "api.example.com",
		Token:            "token-b",
		KeyAuthorization: "token-b.thumbprint",
	})
	if startErr == nil {
		t.Fatal("expected start error, got nil")
	}
	if _, ok := handler.Resolve("api.example.com", "token-b"); ok {
		t.Fatal("token should be cleaned up on failed challenge start")
	}
}

func TestHTTP01HandlerDeleteDomain(t *testing.T) {
	handler := NewHTTP01Handler()
	if err := handler.Set("api.example.com", "token-a", "ka-a"); err != nil {
		t.Fatalf("Set token-a returned error: %v", err)
	}
	if err := handler.Set("api.example.com", "token-b", "ka-b"); err != nil {
		t.Fatalf("Set token-b returned error: %v", err)
	}

	handler.DeleteDomain("api.example.com")

	if _, ok := handler.Resolve("api.example.com", "token-a"); ok {
		t.Fatal("token-a should be cleaned up by DeleteDomain")
	}
	if _, ok := handler.Resolve("api.example.com", "token-b"); ok {
		t.Fatal("token-b should be cleaned up by DeleteDomain")
	}
}
