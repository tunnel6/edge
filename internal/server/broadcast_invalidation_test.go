package server

import "testing"

func TestBroadcastOverflowInvalidatesOnlyMatchingSlowSession(t *testing.T) {
	hub := NewPushBroadcaster(8)
	defer hub.Close()
	a := &Session{ID: "a", DeviceID: "device-a"}
	c := &Session{ID: "c", DeviceID: "device-c"}
	ach, _ := hub.Subscribe(a.ID, 1, a.acceptsBroadcast)
	invalidA := hub.Invalidated(a.ID)
	cch, _ := hub.Subscribe(c.ID, 1, c.acceptsBroadcast)
	invalidC := hub.Invalidated(c.ID)
	entry := broadcastEntry{kind: kindRawBytes, rawData: []byte{1}, rawTargetClients: map[string]struct{}{"device-a": {}}}
	hub.Publish(entry)
	hub.Publish(entry)
	select {
	case <-invalidA:
	default:
		t.Fatal("overflow must invalidate even without a later publication")
	}
	select {
	case <-invalidC:
		t.Fatal("unrelated recipient was invalidated")
	default:
	}
	select {
	case <-cch:
		t.Fatal("targeted event entered unrelated queue")
	default:
	}
	if hub.SubscriberCount() != 1 || hub.DropCount() != 1 {
		t.Fatal("overflow affected unrelated subscribers")
	}
	<-ach
	if _, open := <-ach; open {
		t.Fatal("invalidated data queue remains open")
	}
	hub.Publish(broadcastEntry{kind: kindRawBytes, rawData: []byte{2}, rawTargetClients: map[string]struct{}{"device-c": {}}})
	select {
	case <-cch:
	default:
		t.Fatal("healthy subscriber no longer receives")
	}
}

func TestBroadcastHistoryUsesCurrentRecipientFilter(t *testing.T) {
	hub := NewPushBroadcaster(8)
	defer hub.Close()
	hub.Publish(broadcastEntry{kind: kindRawBytes, rawTargetClients: map[string]struct{}{"device-a": {}}})
	c := &Session{ID: "c", DeviceID: "device-c"}
	_, history := hub.Subscribe(c.ID, 1, c.acceptsBroadcast)
	if len(history) != 0 {
		t.Fatal("history bypassed recipient filtering")
	}
}
