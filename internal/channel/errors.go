package channel

import chtype "icool.io/yat/edge/internal/channel/types"

// Re-export from types/.
var (
	ErrChannelNotFound    = chtype.ErrChannelNotFound
	ErrChannelNotActive   = chtype.ErrChannelNotActive
	ErrInvalidChannelType = chtype.ErrInvalidChannelType
	ErrDomainInUse        = chtype.ErrDomainInUse
	ErrPortInUse          = chtype.ErrPortInUse
	ErrNoAvailablePort    = chtype.ErrNoAvailablePort
	ErrLimitExceeded      = chtype.ErrLimitExceeded
)
