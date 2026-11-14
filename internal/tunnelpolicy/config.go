package tunnelpolicy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ResolveOwnershipFieldsFromConfig extracts ownership-related device IDs from tunnel config JSON.
// Precedence keeps top-level payload over nested config payload for compatibility.
func ResolveOwnershipFieldsFromConfig(configJSON string) (managerDeviceID, creatorDeviceID, publisherDeviceID string) {
	raw := strings.TrimSpace(configJSON)
	if raw == "" {
		return "", "", ""
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return "", "", ""
	}
	read := func(obj map[string]any, key string) string {
		if obj == nil {
			return ""
		}
		value, ok := obj[key]
		if !ok {
			return ""
		}
		return strings.TrimSpace(fmt.Sprintf("%v", value))
	}

	configObj, _ := payload["config"].(map[string]any)
	managerDeviceID = firstNonEmpty(
		read(payload, "managerDeviceId"),
		read(configObj, "managerDeviceId"),
		read(payload, "operatorDeviceId"),
		read(configObj, "operatorDeviceId"),
		read(payload, "ownerDeviceId"),
		read(configObj, "ownerDeviceId"),
	)
	creatorDeviceID = firstNonEmpty(
		read(payload, "creatorDeviceId"),
		read(configObj, "creatorDeviceId"),
		read(payload, "originDeviceId"),
		read(configObj, "originDeviceId"),
	)
	publisherDeviceID = firstNonEmpty(
		read(payload, "publisherDeviceId"),
		read(configObj, "publisherDeviceId"),
	)
	return managerDeviceID, creatorDeviceID, publisherDeviceID
}

// ResolveOwnershipDeviceID returns the best ownership identity in manager -> creator -> publisher order.
func ResolveOwnershipDeviceID(configJSON string) string {
	managerDeviceID, creatorDeviceID, publisherDeviceID := ResolveOwnershipFieldsFromConfig(configJSON)
	return firstNonEmpty(managerDeviceID, creatorDeviceID, publisherDeviceID)
}

// ResolveSharedModeFromConfig parses explicit shared/exclusive state.
// known=false means no explicit shared marker can be trusted from config.
func ResolveSharedModeFromConfig(configJSON string) (known bool, exclusive bool) {
	raw := strings.TrimSpace(configJSON)
	if raw == "" {
		return false, false
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return false, false
	}

	read := func(obj map[string]any, key string) (any, bool) {
		if obj == nil {
			return nil, false
		}
		value, ok := obj[key]
		return value, ok
	}
	resolve := func(value any, ok bool) (bool, bool) {
		if !ok {
			return false, false
		}
		switch typed := value.(type) {
		case bool:
			return true, !typed
		case string:
			normalized := strings.ToLower(strings.TrimSpace(typed))
			switch normalized {
			case "shared", "true":
				return true, false
			case "exclusive", "false":
				return true, true
			default:
				return false, false
			}
		default:
			return false, false
		}
	}

	configObj, _ := payload["config"].(map[string]any)
	candidates := [][2]any{
		{payload, "sharedState"},
		{configObj, "sharedState"},
		{payload, "tunnelSharedState"},
		{configObj, "tunnelSharedState"},
		{payload, "shared"},
		{configObj, "shared"},
	}
	for _, item := range candidates {
		obj, _ := item[0].(map[string]any)
		key, _ := item[1].(string)
		value, ok := read(obj, key)
		if resolvedKnown, resolvedExclusive := resolve(value, ok); resolvedKnown {
			return true, resolvedExclusive
		}
	}
	return false, false
}

// ResolvePublisherProtectedDeviceIDs returns device IDs that should be treated as publisher identities.
func ResolvePublisherProtectedDeviceIDs(configJSON string) map[string]struct{} {
	raw := strings.TrimSpace(configJSON)
	if raw == "" {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil
	}

	out := make(map[string]struct{})
	add := func(value string) {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			return
		}
		out[normalized] = struct{}{}
	}
	read := func(obj map[string]any, key string) string {
		if obj == nil {
			return ""
		}
		value, ok := obj[key]
		if !ok {
			return ""
		}
		return strings.TrimSpace(fmt.Sprintf("%v", value))
	}

	configObj, _ := payload["config"].(map[string]any)
	add(read(payload, "operatorDeviceId"))
	add(read(configObj, "operatorDeviceId"))
	add(read(payload, "ownerDeviceId"))
	add(read(configObj, "ownerDeviceId"))
	add(read(payload, "managerDeviceId"))
	add(read(configObj, "managerDeviceId"))
	add(read(payload, "creatorDeviceId"))
	add(read(configObj, "creatorDeviceId"))
	add(read(payload, "originDeviceId"))
	add(read(configObj, "originDeviceId"))
	add(read(payload, "publisherDeviceId"))
	add(read(configObj, "publisherDeviceId"))

	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
