package relay

import (
	"net"
	"testing"
	"time"
)

func TestObservationPreservesRawSampleIncludingNeverHandshakedPeer(t *testing.T) {
	now := time.Now()
	ep := ObservedEndpoint{InterfaceGeneration: "runtime-1", PublicKey: "key", StartedAt: now, SampledAt: now.Add(time.Millisecond),
		Endpoint: &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 51820}, RxBytes: 42}
	raw := observationFromEndpoint("net", ep)
	if raw.NetworkID != "net" || raw.InterfaceGeneration != ep.InterfaceGeneration || raw.PublicKey != ep.PublicKey || raw.Endpoint != ep.Endpoint.String() ||
		raw.StartedAt != ep.StartedAt || raw.SampledAt != ep.SampledAt || raw.RxBytes != 42 || !raw.LastHandshakeTime.IsZero() {
		t.Fatal("raw sample was filtered or lost source metadata")
	}
	ep.Endpoint.Port = 60000
	if raw.Endpoint != "198.51.100.1:51820" {
		t.Fatal("raw observation aliases endpoint")
	}
	ep.Endpoint = nil
	if observationFromEndpoint("net", ep).Endpoint != "" {
		t.Fatal("missing endpoint fabricated")
	}
}
