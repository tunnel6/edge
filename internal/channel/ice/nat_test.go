package ice

import (
	"net"
	"testing"

	p2p "icool.io/yat/edge/internal/channel/p2p"
)

func TestNATDetectorConeNAT(t *testing.T) {
	d := NewNATDetector()
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}
	addrAlt := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}

	d.RecordProbe("ufrag-1", addr, false)
	d.RecordProbe("ufrag-1", addrAlt, true)

	natType, ok := d.Detect("ufrag-1")
	if !ok {
		t.Fatal("expected detection to succeed")
	}
	if natType != p2p.NATFullCone {
		t.Fatalf("expected full_cone, got %s", natType)
	}
}

func TestNATDetectorSymmetricNAT(t *testing.T) {
	d := NewNATDetector()
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}
	addrAlt := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5001}

	d.RecordProbe("ufrag-2", addr, false)
	d.RecordProbe("ufrag-2", addrAlt, true)

	natType, ok := d.Detect("ufrag-2")
	if !ok {
		t.Fatal("expected detection to succeed")
	}
	if natType != p2p.NATSymmetric {
		t.Fatalf("expected symmetric, got %s", natType)
	}
}

func TestNATDetectorIncomplete(t *testing.T) {
	d := NewNATDetector()
	d.RecordProbe("ufrag-3", &net.UDPAddr{Port: 5000}, false)

	_, ok := d.Detect("ufrag-3")
	if ok {
		t.Fatal("expected detection to fail with only primary probe")
	}
}

func TestNATDetectorFilterProbeRestrictedCone(t *testing.T) {
	d := NewNATDetector()
	d.RecordProbe("ufrag-4", &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}, false)
	d.RecordProbe("ufrag-4", &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}, true)

	target, started := d.StartFilterProbe("ufrag-4")
	if !started || target == nil {
		t.Fatal("expected filter probe to start")
	}
	natType, ok := d.RecordFilterProbeResult("ufrag-4", true)
	if !ok {
		t.Fatal("expected filter probe result recorded")
	}
	if natType != p2p.NATRestrictedCone {
		t.Fatalf("expected restricted_cone, got %s", natType)
	}
	detected, ok := d.Detect("ufrag-4")
	if !ok {
		t.Fatal("expected detect after filter probe")
	}
	if detected != p2p.NATRestrictedCone {
		t.Fatalf("expected restricted_cone detect, got %s", detected)
	}
}

func TestNATDetectorFilterProbePortRestricted(t *testing.T) {
	d := NewNATDetector()
	d.RecordProbe("ufrag-5", &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}, false)
	d.RecordProbe("ufrag-5", &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}, true)

	if _, started := d.StartFilterProbe("ufrag-5"); !started {
		t.Fatal("expected filter probe to start")
	}
	natType, ok := d.RecordFilterProbeResult("ufrag-5", false)
	if !ok {
		t.Fatal("expected filter probe result recorded")
	}
	if natType != p2p.NATPortRestricted {
		t.Fatalf("expected port_restricted, got %s", natType)
	}
	detected, ok := d.Detect("ufrag-5")
	if !ok {
		t.Fatal("expected detect after filter probe")
	}
	if detected != p2p.NATPortRestricted {
		t.Fatalf("expected port_restricted detect, got %s", detected)
	}
}

func TestNATDetectorFilterProbeNotStartedForSymmetric(t *testing.T) {
	d := NewNATDetector()
	d.RecordProbe("ufrag-6", &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000}, false)
	d.RecordProbe("ufrag-6", &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5001}, true)

	if _, started := d.StartFilterProbe("ufrag-6"); started {
		t.Fatal("expected filter probe not started for symmetric mapping")
	}
}
