package httpproxy

import (
	"fmt"
	"time"

	ct "icool.io/yat/edge/internal/channel/types"
	logger "icool.io/yat/edge/pkg/log"
)

func (p *HTTPProxy) Upsert(target *ct.Channel, previous *ct.Channel) error {
	if p == nil || target == nil {
		return nil
	}

	if previous != nil {
		oldSub := previous.RouteSubdomain()
		newSub := target.RouteSubdomain()
		if oldSub != "" && oldSub != newSub {
			p.UnregisterSubdomain(oldSub)
		}

		oldAlias := normalizeDomain(previous.AliasDomain)
		newAlias := normalizeDomain(target.AliasDomain)
		if oldAlias != "" && oldAlias != newAlias {
			p.Unregister(oldAlias)
		}
	}

	if sub := target.RouteSubdomain(); sub != "" {
		p.RegisterSubdomain(sub, target)
	}
	if alias := normalizeDomain(target.AliasDomain); alias != "" {
		p.RegisterDomain(alias, target)
	}

	return nil
}

func (p *HTTPProxy) Remove(target *ct.Channel) error {
	if p == nil || target == nil {
		return nil
	}
	if sub := target.RouteSubdomain(); sub != "" {
		p.UnregisterSubdomain(sub)
	}
	if alias := normalizeDomain(target.AliasDomain); alias != "" {
		p.Unregister(alias)
	}
	return nil
}

func (p *HTTPProxy) HandleData(_ *ct.Channel, connectionID string, _ uint32, data []byte, flags uint8) error {
	if p == nil {
		return nil
	}
	return p.HandleDataPacket(connectionID, data, flags)
}

// HandleDataPacket routes incoming data to the appropriate HTTP connection.
func (p *HTTPProxy) HandleDataPacket(connectionID string, data []byte, flags uint8) error {
	conn, ok := p.connections.Load(connectionID)
	if !ok {
		return fmt.Errorf("connection not found: %s", connectionID)
	}

	hc := conn.(*httpConnection)

	if len(data) > 0 {
		select {
		case hc.dataCh <- data:
		case <-hc.finished:
			return nil
		case <-time.After(5 * time.Second):
			logger.Warnf("send data timeout: %s", connectionID)
			return fmt.Errorf("timeout")
		}
	}

	if flags&0x03 != 0 {
		close(hc.finished)
		p.connections.Delete(connectionID)
	}

	return nil
}
