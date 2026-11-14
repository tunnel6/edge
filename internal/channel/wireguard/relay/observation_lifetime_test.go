package relay

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestObservationLifetimeRetirementAndRecreation(t *testing.T) {
	var source observationLifetimes
	sample := Observation{NetworkID: "net", InterfaceGeneration: "first"}
	consume := func() error { return nil }
	if source.withCurrent(sample, consume) == nil {
		t.Fatal("unpublished interface accepted")
	}
	if source.publish("net", "") == nil || source.publish("", "first") == nil {
		t.Fatal("missing identity accepted")
	}
	if err := source.publish("net", "first"); err != nil {
		t.Fatal(err)
	}
	if err := source.withCurrent(sample, consume); err != nil {
		t.Fatal(err)
	}
	want := errors.New("consumer error")
	if err := source.withCurrent(sample, func() error { return want }); !errors.Is(err, want) {
		t.Fatal("consumer error lost")
	}
	if source.withCurrent(sample, nil) == nil {
		t.Fatal("nil consumer accepted")
	}
	if err := source.retire("net"); err != nil {
		t.Fatal(err)
	}
	if source.withCurrent(sample, consume) == nil {
		t.Fatal("retired interface accepted before kernel cleanup")
	}
	if err := source.publish("net", "second"); err != nil {
		t.Fatal(err)
	}
	if source.withCurrent(sample, consume) == nil {
		t.Fatal("old generation revived by recreation")
	}
	sample.InterfaceGeneration = "second"
	if err := source.withCurrent(sample, consume); err != nil {
		t.Fatal(err)
	}
	if err := source.publish("other", "third"); err != nil {
		t.Fatal(err)
	}
	if err := source.retireAll(); err != nil {
		t.Fatal(err)
	}
	if source.withCurrent(sample, consume) == nil || source.withCurrent(Observation{NetworkID: "other", InterfaceGeneration: "third"}, consume) == nil {
		t.Fatal("stop retained a lifetime")
	}
}

func TestObservationLifetimeBindingSerializesAndDetachesByIdentity(t *testing.T) {
	var source observationLifetimes
	if _, err := source.bind(nil); err == nil {
		t.Fatal("nil gate accepted")
	}
	var authority sync.Mutex
	entered := make(chan struct{}, 1)
	detach, err := source.bind(func(change func() error) error {
		entered <- struct{}{}
		authority.Lock()
		defer authority.Unlock()
		return change()
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.bind(func(change func() error) error { return change() }); err == nil {
		t.Fatal("second authority accepted")
	}
	authority.Lock()
	done := make(chan error, 1)
	go func() { done <- source.publish("net", "first") }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("mutation did not reach authority")
	}
	if source.withCurrent(Observation{NetworkID: "net", InterfaceGeneration: "first"}, func() error { return nil }) == nil {
		t.Fatal("mutation bypassed in-flight authority work")
	}
	detached := make(chan struct{})
	go func() { detach(); close(detached) }()
	select {
	case <-detached:
		t.Fatal("detach did not wait for mutation")
	case <-time.After(20 * time.Millisecond):
	}
	authority.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-detached
	calls := 0
	newDetach, err := source.bind(func(change func() error) error { calls++; return change() })
	if err != nil {
		t.Fatal(err)
	}
	defer newDetach()
	detach()
	if err := source.retire("net"); err != nil || calls != 1 {
		t.Fatal("late old detach removed replacement authority", err, calls)
	}
}

func TestObservationLifetimeConsumerPinsRetirement(t *testing.T) {
	var source observationLifetimes
	if err := source.publish("net", "first"); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- source.withCurrent(Observation{NetworkID: "net", InterfaceGeneration: "first"}, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	retired := make(chan error, 1)
	go func() { retired <- source.retire("net") }()
	select {
	case <-retired:
		t.Fatal("lifetime retired inside pinned consumer")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-retired; err != nil {
		t.Fatal(err)
	}
}
