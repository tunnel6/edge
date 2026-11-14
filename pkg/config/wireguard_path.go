package config

import "time"

// WireGuardPathConfig is an explicit, local-only opt-in. No defaults are
// supplied and this configuration never advertises client/platform capability.
type WireGuardPathConfig struct {
	// Bounds the admission gate across readiness and bilateral application.
	// Zero uses phases.prepare + phases.apply; expired COMMIT remains replayable.
	TransactionTimeout time.Duration `yaml:"transaction_timeout"`
	Phases             struct {
		Prepare time.Duration `yaml:"prepare"`
		Apply   time.Duration `yaml:"apply"`
	} `yaml:"phases"`
	RegistryMembers int           `yaml:"registry_members"`
	MaxPairs        int           `yaml:"max_pairs"`
	ControlBurst    int           `yaml:"control_burst"` // in-flight switches per network/member, both participants
	TickInterval    time.Duration `yaml:"tick_interval"`
}
