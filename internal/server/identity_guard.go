package server

import (
	"fmt"
	"strings"
)

const deviceOwnerUserIDPrefix = "device:"

func buildDeviceOwnerUserID(deviceID string) string {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return ""
	}
	return deviceOwnerUserIDPrefix + deviceID
}

// The wire protocol retains user_id as a resource-owner scope. In standalone
// mode its only valid value is derived from the verified device certificate.
func resolveAuthenticatedSessionIdentity(certDeviceID, requestedUserID, requestedDeviceID string) (string, string, error) {
	deviceID := strings.TrimSpace(certDeviceID)
	requestedDeviceID = strings.TrimSpace(requestedDeviceID)
	requestedUserID = strings.TrimSpace(requestedUserID)
	ownerScope := buildDeviceOwnerUserID(deviceID)
	if deviceID == "" || (requestedDeviceID != "" && requestedDeviceID != deviceID) || (requestedUserID != "" && requestedUserID != ownerScope) {
		return "", "", fmt.Errorf("%w: request does not match certificate device", ErrAuthIdentityMismatch)
	}
	return ownerScope, deviceID, nil
}

func resolveSessionCSRIdentity(sessionUserID, sessionDeviceID, requestedUserID, requestedDeviceID string) (string, string, error) {
	sessUID := strings.TrimSpace(sessionUserID)
	sessDID := strings.TrimSpace(sessionDeviceID)
	reqUID := strings.TrimSpace(requestedUserID)
	reqDID := strings.TrimSpace(requestedDeviceID)
	if sessDID == "" || sessUID != buildDeviceOwnerUserID(sessDID) {
		return "", "", fmt.Errorf(
			"%w: invalid session identity user=%q device=%q",
			ErrCSRIdentityMismatch,
			sessUID,
			sessDID,
		)
	}

	if reqUID != "" && reqUID != sessUID {
		return "", "", fmt.Errorf(
			"%w: requested user %q does not match session user %q",
			ErrCSRIdentityMismatch,
			reqUID,
			sessUID,
		)
	}
	if reqDID != "" && reqDID != sessDID {
		return "", "", fmt.Errorf(
			"%w: requested device %q does not match session device %q",
			ErrCSRIdentityMismatch,
			reqDID,
			sessDID,
		)
	}

	return sessUID, sessDID, nil
}
