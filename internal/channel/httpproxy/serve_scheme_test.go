package httpproxy

import (
	"net/http/httptest"
	"strings"
	"testing"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	ct "icool.io/yat/edge/internal/channel/types"
)

func TestIsRequestSchemeAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target *ct.Channel
		isTLS  bool
		want   bool
	}{
		{
			name:   "nil target defaults allow",
			target: nil,
			isTLS:  true,
			want:   true,
		},
		{
			name:   "http channel allows plain http",
			target: &ct.Channel{Type: fbMsg.ChannelTypeHTTP},
			isTLS:  false,
			want:   true,
		},
		{
			name:   "http channel blocks https",
			target: &ct.Channel{Type: fbMsg.ChannelTypeHTTP},
			isTLS:  true,
			want:   false,
		},
		{
			name:   "https channel allows https",
			target: &ct.Channel{Type: fbMsg.ChannelTypeHTTPS},
			isTLS:  true,
			want:   true,
		},
		{
			name:   "https channel blocks plain http",
			target: &ct.Channel{Type: fbMsg.ChannelTypeHTTPS},
			isTLS:  false,
			want:   false,
		},
		{
			name:   "non-web channel defaults allow",
			target: &ct.Channel{Type: fbMsg.ChannelTypeTCP},
			isTLS:  true,
			want:   true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isRequestSchemeAllowed(tc.target, tc.isTLS)
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestBuildSchemeErrorMessage(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("GET", "https://tem7zf.jp.myproxy.dev/path?a=1", nil)
	target := &ct.Channel{Type: fbMsg.ChannelTypeHTTP}

	got := buildSchemeErrorMessage(target, "tem7zf.jp.myproxy.dev", req)
	wantContains := []string{
		"scheme error: use http://tem7zf.jp.myproxy.dev/path?a=1",
		"current request: https://tem7zf.jp.myproxy.dev/path?a=1",
	}

	for _, token := range wantContains {
		if !strings.Contains(got, token) {
			t.Fatalf("expected message to contain %q, got %q", token, got)
		}
	}
}
