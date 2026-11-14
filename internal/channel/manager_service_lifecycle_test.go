package channel

import (
	"errors"
	"reflect"
	"testing"
)

type lifecycleFixtureService struct {
	name     string
	trace    *[]string
	startErr error
	stopErr  error
}

func (s *lifecycleFixtureService) Start() error {
	*s.trace = append(*s.trace, "start "+s.name)
	return s.startErr
}

func (s *lifecycleFixtureService) Stop() error {
	*s.trace = append(*s.trace, "stop "+s.name)
	return s.stopErr
}

func TestManagerStartupFailureDrainsEnteredServicesInReverseOrder(t *testing.T) {
	startErr, stopErr := errors.New("startup fixture failure"), errors.New("stop fixture failure")
	var trace []string
	m := &ChannelManager{managedServices: []Service{
		&lifecycleFixtureService{name: "mesh", trace: &trace},
		&lifecycleFixtureService{name: "owner", trace: &trace, startErr: startErr, stopErr: stopErr},
		&lifecycleFixtureService{name: "later", trace: &trace},
	}}
	err := m.Start()
	if !errors.Is(err, startErr) || !errors.Is(err, stopErr) || m.started {
		t.Fatal("startup lost a lifecycle error or published success", err)
	}
	want := []string{"start mesh", "start owner", "stop owner", "stop mesh"}
	if !reflect.DeepEqual(trace, want) {
		t.Fatalf("lifecycle order: got %v, want %v", trace, want)
	}
}

func TestManagerStopContinuesDrainAndRetainsAllErrors(t *testing.T) {
	ownerErr, meshErr := errors.New("owner fixture failure"), errors.New("mesh fixture failure")
	var trace []string
	m := &ChannelManager{started: true, managedServices: []Service{
		&lifecycleFixtureService{name: "mesh", trace: &trace, stopErr: meshErr},
		&lifecycleFixtureService{name: "owner", trace: &trace, stopErr: ownerErr},
	}}
	err := m.Stop()
	if !errors.Is(err, ownerErr) || !errors.Is(err, meshErr) || m.started {
		t.Fatal("stop lost an error or retained started state", err)
	}
	if !reflect.DeepEqual(trace, []string{"stop owner", "stop mesh"}) {
		t.Fatal("stop failed to drain remaining service", trace)
	}
}
