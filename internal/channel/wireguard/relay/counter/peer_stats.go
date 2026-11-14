package counter

// PeerStats holds per-peer traffic statistics.
type PeerStats struct {
	Bytes   uint64
	Packets uint64
	Dropped uint64
}
