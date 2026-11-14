package server

import (
	"errors"
	"testing"
)

func TestResolveAuthenticatedSessionIdentity(t *testing.T) {
	for _, requested := range []string{"", "device:device-a"} {
		userID, deviceID, err := resolveAuthenticatedSessionIdentity(" device-a ", requested, "device-a")
		if err != nil || userID != "device:device-a" || deviceID != "device-a" {
			t.Fatalf("invalid device identity: %q %q %v", userID, deviceID, err)
		}
	}
	for _, request := range [][3]string{{"", "", ""}, {"device-a", "account-123", "device-a"}, {"device-a", "", "other-device"}} {
		_, _, err := resolveAuthenticatedSessionIdentity(request[0], request[1], request[2])
		if !errors.Is(err, ErrAuthIdentityMismatch) {
			t.Fatalf("expected identity mismatch for %v: %v", request, err)
		}
	}
}

func TestResolveSessionCSRIdentity(t *testing.T) {
	t.Run("inherits identity from session when request fields empty", func(t *testing.T) {
		userID, deviceID, err := resolveSessionCSRIdentity(" device:device-a ", " device-a ", "", "")
		if err != nil {
			t.Fatalf("resolveSessionCSRIdentity returned error: %v", err)
		}
		if userID != "device:device-a" || deviceID != "device-a" {
			t.Fatalf("resolved identity mismatch: user=%q device=%q", userID, deviceID)
		}
	})

	t.Run("rejects mismatched user", func(t *testing.T) {
		_, _, err := resolveSessionCSRIdentity("device:device-a", "device-a", "device:device-b", "device-a")
		if err == nil {
			t.Fatalf("expected mismatch error")
		}
		if !errors.Is(err, ErrCSRIdentityMismatch) {
			t.Fatalf("expected ErrCSRIdentityMismatch, got=%v", err)
		}
	})

	t.Run("rejects mismatched device", func(t *testing.T) {
		_, _, err := resolveSessionCSRIdentity("device:device-a", "device-a", "device:device-a", "device-b")
		if err == nil {
			t.Fatalf("expected mismatch error")
		}
		if !errors.Is(err, ErrCSRIdentityMismatch) {
			t.Fatalf("expected ErrCSRIdentityMismatch, got=%v", err)
		}
	})
}
