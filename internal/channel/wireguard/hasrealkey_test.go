package wireguard

import "testing"

func TestHasRealPublicKeyWithInvalidKeys(t *testing.T) {
	tests := []struct {
		name      string
		member    *NetworkMember
		wantReal  bool
	}{
		{
			name:     "nil member",
			member:   nil,
			wantReal: false,
		},
		{
			name:     "empty public key",
			member:   &NetworkMember{ClientID: "device-x", PublicKey: ""},
			wantReal: false,
		},
		{
			name:     "placeholder key equals clientID",
			member:   &NetworkMember{ClientID: "device-x", PublicKey: "device-x"},
			wantReal: false,
		},
		{
			name:     "invalid key - member ID format",
			member:   &NetworkMember{ClientID: "device-y", PublicKey: "member-3-device-f9lnqpbh6ots5ke7z2mh5-net_fhaf"},
			wantReal: false,
		},
		{
			name:     "invalid key - short string",
			member:   &NetworkMember{ClientID: "device-z", PublicKey: "pub-a"},
			wantReal: false,
		},
		{
			name:     "valid WireGuard key",
			member:   &NetworkMember{ClientID: "device-w", PublicKey: "2i5f2t366s/S9CQfAj+oemY3DhaspTjZJ+mroH8FzXY="},
			wantReal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasRealPublicKey(tt.member)
			if got != tt.wantReal {
				t.Errorf("hasRealPublicKey() = %v, want %v", got, tt.wantReal)
			}
		})
	}
}
