package server

import (
	"fmt"

	flatbuffers "github.com/google/flatbuffers/go"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
)

const maxAuthCapabilities = 1024

const (
	authSlotUserID              flatbuffers.VOffsetT = 4
	authSlotCapabilitiesLegacy  flatbuffers.VOffsetT = 10
	authSlotCapabilitiesCurrent flatbuffers.VOffsetT = 12
)

// parseAuthRequestSafe parses user_id and capabilities defensively. It supports
// both legacy and current AuthRequest layouts and prevents panics on malformed
// payloads.
func parseAuthRequestSafe(authReq *fbMsg.AuthRequest) (userID string, caps []string, err error) {
	if authReq == nil {
		return "", nil, fmt.Errorf("auth request is nil")
	}

	tab := authReq.Table()
	userID, _, err = stringFieldBySlot(&tab, authSlotUserID)
	if err != nil {
		return "", nil, fmt.Errorf("parse user_id: %w", err)
	}

	// Prefer current layout first, then fallback to legacy slot.
	caps, present, errCurrent := stringVectorBySlot(&tab, authSlotCapabilitiesCurrent)
	if errCurrent == nil && present {
		return userID, caps, nil
	}

	capsLegacy, presentLegacy, errLegacy := stringVectorBySlot(&tab, authSlotCapabilitiesLegacy)
	if errLegacy == nil && presentLegacy {
		return userID, capsLegacy, nil
	}

	if errCurrent != nil && errLegacy != nil {
		return "", nil, fmt.Errorf("parse capabilities failed for both layouts: current=%v, legacy=%v", errCurrent, errLegacy)
	}

	// Missing capabilities is treated as empty capability set for compatibility.
	return userID, []string{}, nil
}

func stringFieldBySlot(tab *flatbuffers.Table, slot flatbuffers.VOffsetT) (value string, present bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			value = ""
			present = false
			err = fmt.Errorf("panic while reading field slot %d: %v", slot, r)
		}
	}()

	if tab == nil {
		return "", false, fmt.Errorf("table is nil")
	}

	o := flatbuffers.UOffsetT(tab.Offset(slot))
	if o == 0 {
		return "", false, nil
	}
	return string(tab.ByteVector(o + tab.Pos)), true, nil
}

func stringVectorBySlot(tab *flatbuffers.Table, slot flatbuffers.VOffsetT) (values []string, present bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			values = nil
			present = false
			err = fmt.Errorf("panic while reading vector slot %d: %v", slot, r)
		}
	}()

	if tab == nil {
		return nil, false, fmt.Errorf("table is nil")
	}

	o := flatbuffers.UOffsetT(tab.Offset(slot))
	if o == 0 {
		return nil, false, nil
	}

	length := tab.VectorLen(o)
	if length < 0 || length > maxAuthCapabilities {
		return nil, false, fmt.Errorf("invalid vector length at slot %d: %d", slot, length)
	}

	vec := tab.Vector(o)
	values = make([]string, 0, length)
	for i := 0; i < length; i++ {
		values = append(values, string(tab.ByteVector(vec+flatbuffers.UOffsetT(i*4))))
	}

	return values, true, nil
}
