package channel

import (
	"net"

	chtype "icool.io/yat/edge/internal/channel/types"
)

// Re-export from types/.
type HTTPHeader = chtype.HTTPHeader
type Protocol = chtype.Protocol

type HandlerContext struct {
	chtype.SessionIdentity // immutable session snapshot (SessionID, UserID, DeviceID, Hostname, Capabilities)
	Conn         net.Conn
	Protocol     Protocol

	Manager *ChannelManager
}
