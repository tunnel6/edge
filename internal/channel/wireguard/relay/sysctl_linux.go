//go:build linux

package relay

import (
	"fmt"
	"os"
	"strings"
)

// SysctlWarning describes a missing or incorrect kernel parameter.
type SysctlWarning struct {
	Key      string
	Expected string
	Actual   string
	Message  string
}

// CheckRequiredSysctl verifies that the kernel parameters required for
// WireGuard relay forwarding are correctly configured.  It returns a list
// of warnings but never blocks startup — the caller decides how to handle them.
func CheckRequiredSysctl() []SysctlWarning {
	var warnings []SysctlWarning

	checks := []struct {
		key      string
		expected string
		desc     string
	}{
		{"net/ipv4/ip_forward", "1", "IP forwarding must be enabled for relay forwarding"},
		{"net/ipv4/conf/all/rp_filter", "0", "Reverse path filtering must be disabled for same-interface forwarding"},
	}

	for _, c := range checks {
		val, err := readSysctl(c.key)
		if err != nil {
			warnings = append(warnings, SysctlWarning{
				Key:      c.key,
				Expected: c.expected,
				Message:  fmt.Sprintf("cannot read %s: %v", c.key, err),
			})
			continue
		}
		val = strings.TrimSpace(val)
		if val != c.expected {
			warnings = append(warnings, SysctlWarning{
				Key:      c.key,
				Expected: c.expected,
				Actual:   val,
				Message:  fmt.Sprintf("%s (current=%s, expected=%s)", c.desc, val, c.expected),
			})
		}
	}

	return warnings
}

// readSysctl reads a single value from /proc/sys.
func readSysctl(key string) (string, error) {
	path := "/proc/sys/" + key
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
