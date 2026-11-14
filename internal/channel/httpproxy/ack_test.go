package httpproxy

import (
	"testing"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	ct "icool.io/yat/edge/internal/channel/types"
)

func TestShouldEnableHTTPSFlow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		channelType fbMsg.ChannelType
		createReq   *ct.CreateRequest
		parsedCfg   *channelCreateConfig
		want        bool
	}{
		{
			name:        "https channel type enables flow",
			channelType: fbMsg.ChannelTypeHTTPS,
			want:        true,
		},
		{
			name:        "http channel with https protocol enables flow",
			channelType: fbMsg.ChannelTypeHTTP,
			createReq:   &ct.CreateRequest{Protocol: "https"},
			want:        true,
		},
		{
			name:        "http channel with config https enables flow",
			channelType: fbMsg.ChannelTypeHTTP,
			parsedCfg:   &channelCreateConfig{EnableHTTPS: true},
			want:        true,
		},
		{
			name:        "http channel without https signal disables flow",
			channelType: fbMsg.ChannelTypeHTTP,
			createReq:   &ct.CreateRequest{Protocol: "http"},
			parsedCfg:   &channelCreateConfig{},
			want:        false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := shouldEnableHTTPSFlow(tc.channelType, tc.createReq, tc.parsedCfg)
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestBuildAliasDomainDNSMetaWithoutDNS01(t *testing.T) {
	t.Parallel()

	meta, ok := buildAliasDomainDNSMeta("demo.example.com", "abc.e.example.com", false)
	if !ok {
		t.Fatalf("expected dns meta to be generated")
	}
	if meta.DNSRequired != true {
		t.Fatalf("expected dns_required=true")
	}
	if meta.DNS01RecordType != "" || meta.DNS01RecordName != "" || meta.DNS01RecordValue != "" || meta.DNS01Hint != "" {
		t.Fatalf("expected dns01 fields to be empty when includeDNS01=false")
	}
}

func TestResolveAssignedDomainForAliasDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		channelDomain string
		subdomain     string
		baseDomain    string
		wantResolved  string
		wantRecovered bool
		wantErr       string
	}{
		{
			name:          "use channel domain when already fully qualified",
			channelDomain: "abc.e.example.com",
			subdomain:     "abc",
			baseDomain:    "e.example.com",
			wantResolved:  "abc.e.example.com",
			wantRecovered: false,
		},
		{
			name:          "recover with subdomain and base domain",
			channelDomain: "abc",
			subdomain:     "abc",
			baseDomain:    "e.example.com",
			wantResolved:  "abc.e.example.com",
			wantRecovered: true,
		},
		{
			name:          "recover when channel domain is empty",
			channelDomain: "",
			subdomain:     "xyz",
			baseDomain:    "e.example.com",
			wantResolved:  "xyz.e.example.com",
			wantRecovered: true,
		},
		{
			name:          "recover with channel label when subdomain missing",
			channelDomain: "tdkmha",
			subdomain:     "",
			baseDomain:    "e.example.com",
			wantResolved:  "tdkmha.e.example.com",
			wantRecovered: true,
		},
		{
			name:          "return invalid error without usable base domain",
			channelDomain: "tdkmha",
			subdomain:     "tdkmha",
			baseDomain:    "",
			wantErr:       "assigned domain \"tdkmha\" is invalid (missing base domain suffix); check edge assigned_domain configuration",
		},
		{
			name:          "return empty error without any signal",
			channelDomain: "",
			subdomain:     "",
			baseDomain:    "",
			wantErr:       "assigned domain is empty; check edge assigned_domain configuration",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotResolved, gotRecovered, err := resolveAssignedDomainForAliasDomain(
				tc.channelDomain,
				tc.subdomain,
				tc.baseDomain,
			)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotResolved != tc.wantResolved {
				t.Fatalf("expected resolved domain %q, got %q", tc.wantResolved, gotResolved)
			}
			if gotRecovered != tc.wantRecovered {
				t.Fatalf("expected recovered=%v, got %v", tc.wantRecovered, gotRecovered)
			}
		})
	}
}
