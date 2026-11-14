package types

import "errors"

var (
	ErrChannelNotFound          = errors.New("channel not found")
	ErrChannelNotActive         = errors.New("channel not active")
	ErrInvalidChannelType       = errors.New("invalid channel type")
	ErrDomainInUse              = errors.New("domain already in use")
	ErrPortInUse                = errors.New("port already in use")
	ErrNoAvailablePort          = errors.New("no available port")
	ErrLimitExceeded            = errors.New("channel limit exceeded")
	ErrSessionNotFoundForClient = errors.New("session not found for client")
)
