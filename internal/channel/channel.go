package channel

import (
	chtype "icool.io/yat/edge/internal/channel/types"
)

// Re-export types from types/ for backward compatibility.
type State = chtype.State

const (
	StateCreating = chtype.StateCreating
	StateActive   = chtype.StateActive
	StatePaused   = chtype.StatePaused
	StateClosing  = chtype.StateClosing
	StateClosed   = chtype.StateClosed
)

type Channel = chtype.Channel
type ChannelStats = chtype.ChannelStats

var NewChannel = chtype.NewChannel
