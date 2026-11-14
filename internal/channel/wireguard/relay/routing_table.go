package relay

import (
	"fmt"
	"sync"
)

const (
	// routeTableMin is the first route table ID allocated for WireGuard networks.
	// IDs below this range are reserved for system tables:
	//   local=255, main=254, default=253, unspec=0, and user-defined 1-999.
	routeTableMin = 1000

	// routeTableMax is the upper bound (exclusive) for route table allocation.
	// This supports ~64000 concurrent networks.
	routeTableMax = 65000
)

// routeTableAllocator assigns unique Linux routing table IDs to WireGuard
// networks so that each network's CIDR route lives in its own table.
// This prevents route conflicts when multiple networks use overlapping CIDRs.
type routeTableAllocator struct {
	mu     sync.Mutex
	nextID uint32
	inUse  map[string]uint32 // networkID -> tableID
}

func newRouteTableAllocator() *routeTableAllocator {
	return &routeTableAllocator{
		nextID: routeTableMin,
		inUse:  make(map[string]uint32),
	}
}

// Allocate assigns a new route table ID for the given network.
// If the network already has an allocation, the existing ID is returned.
func (a *routeTableAllocator) Allocate(networkID string) (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if id, ok := a.inUse[networkID]; ok {
		return id, nil
	}

	if a.nextID >= routeTableMax {
		return 0, fmt.Errorf("route table ID exhausted (max=%d)", routeTableMax)
	}

	id := a.nextID
	a.nextID++
	a.inUse[networkID] = id
	return id, nil
}

// Release frees the route table ID assigned to a network.
func (a *routeTableAllocator) Release(networkID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.inUse, networkID)
}
