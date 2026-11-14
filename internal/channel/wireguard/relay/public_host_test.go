package relay

import "testing"

func TestNormalizePublicHost(t *testing.T) {
	for input, want := range map[string]string{
		"": "", "wg.example.com": "wg.example.com", "203.0.113.10:443": "203.0.113.10",
		"[2001:db8::10]:443": "2001:db8::10", "2001:db8::10": "2001:db8::10",
		"https://edge.example.com:443": "edge.example.com",
	} {
		got, err := NormalizePublicHost(input)
		if err != nil || got != want {
			t.Fatalf("normalize %q = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"0.0.0.0", "::", "224.0.0.1", "bad host", ":51820", "user@edge.example.com", "edge.example.com/path"} {
		if _, err := NormalizePublicHost(input); err == nil {
			t.Fatalf("accepted invalid public host %q", input)
		}
	}
}
