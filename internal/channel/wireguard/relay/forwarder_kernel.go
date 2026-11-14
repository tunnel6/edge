//go:build linux

package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"icool.io/yat/edge/internal/channel/tc"
	"icool.io/yat/edge/internal/channel/wireguard/relay/counter"
	logger "icool.io/yat/edge/pkg/log"
)

// nftTableName is the dedicated nftables table used by the kernel forwarder.
// Using a private table avoids conflicts with user-managed iptables/nftables rules.
const nftTableName = "yat_relay"

// kernelForwarder relies on the Linux kernel's native ip_forward path for
// same-interface peer-to-peer forwarding. No userspace packet capture or
// injection is performed.
//
// Prerequisites (managed by Start/Stop):
//   - Per-interface rp_filter set to 0
//   - nftables FORWARD rule allowing same-interface traffic (via google/nftables)
//
// Data flow (no userspace hop):
//
//	peerA → WG decrypt → TUN → ip_forward() → wg_xmit → WG encrypt → peerB
type kernelForwarder struct {
	ifName  string
	cidr    string
	relayIP string

	ruleHandle uint64 // nftables forward rule handle for precise cleanup
	mu         sync.Mutex
	started    bool

	// peerCounter provides per-peer traffic statistics via TC BPF.
	peerCounter *counter.PeerCounter
	// rateLimiter provides per-peer egress rate limiting via HTB.
	rateLimiter *tc.RateLimiter
	// rateLimits tracks configured rate limits per peer IP.
	rateLimits map[string]PeerRateLimitInfo
}

// NewKernelForwarder creates a kernel-based forwarder.
func NewKernelForwarder(ifName, cidr, relayIP string) (Forwarder, error) {
	return &kernelForwarder{
		ifName:     ifName,
		cidr:       cidr,
		relayIP:    relayIP,
		rateLimits: make(map[string]PeerRateLimitInfo),
	}, nil
}

func (f *kernelForwarder) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.started {
		return fmt.Errorf("kernel forwarder already started for %s", f.ifName)
	}

	// Disable reverse path filtering. The kernel computes effective rp_filter
	// as max(conf/all/rp_filter, conf/<if>/rp_filter), so BOTH must be 0
	// for the kernel to accept packets arriving on the WG interface whose
	// source IP is routable through a different interface.
	if err := writeSysctl("net/ipv4/conf/all/rp_filter", "0"); err != nil {
		logger.Warnf("kernel forwarder: failed to set all/rp_filter=0: %v", err)
	}
	if err := writeSysctl(fmt.Sprintf("net/ipv4/conf/%s/rp_filter", f.ifName), "0"); err != nil {
		logger.Warnf("kernel forwarder: failed to set rp_filter=0 on %s: %v", f.ifName, err)
	}

	// Ensure global ip_forward is enabled. Required for the kernel to
	// forward decrypted WireGuard packets between peers on the same
	// interface. Without this, packets are silently dropped before
	// reaching the FORWARD netfilter hook.
	if err := writeSysctl("net/ipv4/ip_forward", "1"); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}

	// Clean up any legacy iptables FORWARD rules left over from the pre-nftables
	// era (commit 7d5728f used `iptables -I FORWARD ...`).  The migration to
	// google/nftables (commit 7c0e62d) removed the old functions without
	// cleaning up rules already present on the system.
	cleanupLegacyIPTablesRules(f.ifName, f.cidr)

	// Install nftables FORWARD rule (no masquerade: kernel ip_forward
	// preserves source IP for same-interface forwarding; masquerade
	// would break the return path by rewriting src to the relay IP).
	fwdHandle, err := installNFTForwardRule(f.ifName, f.cidr)
	if err != nil {
		return fmt.Errorf("install nftables forward rule: %w", err)
	}
	f.ruleHandle = fwdHandle

	// Install iptables FORWARD rule as fallback for iptables-legacy compatibility.
	// Docker (and some cloud providers) set the iptables FORWARD chain policy to
	// DROP. On systems using iptables-legacy (instead of iptables-nft), the
	// nftables ACCEPT verdict at mangle priority does NOT bypass the iptables-legacy
	// DROP policy, causing all forwarded packets to be silently dropped.
	// Adding an explicit iptables FORWARD rule ensures compatibility regardless
	// of the iptables backend (legacy or nft).
	if err := installIPTablesForwardRule(f.ifName, f.cidr); err != nil {
		logger.Warnf("kernel forwarder: failed to install iptables fallback rule for %s: %v", f.ifName, err)
	}

	// Start per-peer traffic counter (TC BPF program at priority 10).
	// Non-fatal: may fail if eBPF build tag is not set.
	if pc, err := counter.NewPeerCounter(f.ifName); err == nil {
		if err := pc.Start(); err != nil {
			logger.Warnf("kernel forwarder: peer counter start failed for %s: %v", f.ifName, err)
		} else {
			f.peerCounter = pc
		}
	}

	f.started = true
	logger.Infof("kernel forwarder started: iface=%s cidr=%s relay_ip=%s", f.ifName, f.cidr, f.relayIP)
	return nil
}

func (f *kernelForwarder) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.started {
		return nil
	}

	if err := removeNFTForwardRule(f.ifName, f.cidr, f.ruleHandle); err != nil {
		logger.Warnf("kernel forwarder: failed to remove nftables rule for %s: %v", f.ifName, err)
	}

	// Remove iptables fallback rule.
	if err := removeIPTablesForwardRule(f.ifName, f.cidr); err != nil {
		logger.Warnf("kernel forwarder: failed to remove iptables rule for %s: %v", f.ifName, err)
	}

	// Stop per-peer counter and rate limiter.
	if f.peerCounter != nil {
		if err := f.peerCounter.Stop(); err != nil {
			logger.Warnf("kernel forwarder: peer counter stop failed for %s: %v", f.ifName, err)
		}
		f.peerCounter = nil
	}
	if f.rateLimiter != nil {
		if err := f.rateLimiter.Stop(); err != nil {
			logger.Warnf("kernel forwarder: rate limiter stop failed for %s: %v", f.ifName, err)
		}
		f.rateLimiter = nil
	}
	f.rateLimits = make(map[string]PeerRateLimitInfo)

	f.started = false
	f.ruleHandle = 0
	logger.Infof("kernel forwarder stopped: iface=%s", f.ifName)
	return nil
}

func (f *kernelForwarder) Stats() ForwarderStats {
	f.mu.Lock()
	pc := f.peerCounter
	f.mu.Unlock()
	if pc == nil {
		return ForwarderStats{}
	}
	// Aggregate per-peer BPF stats into a global snapshot, same as eBPF forwarder.
	allStats, err := pc.AllPeerStats()
	if err != nil {
		return ForwarderStats{}
	}
	var total ForwarderStats
	for _, s := range allStats {
		total.Forwarded += s.Packets
		total.Dropped += s.Dropped
	}
	return total
}

func (f *kernelForwarder) Name() string {
	return "kernel"
}

// PeerStats returns per-peer traffic statistics from the TC BPF counter.
func (f *kernelForwarder) PeerStats() map[string]PeerTrafficStats {
	f.mu.Lock()
	pc := f.peerCounter
	f.mu.Unlock()
	if pc == nil {
		return nil
	}
	stats, err := pc.AllPeerStats()
	if err != nil {
		return nil
	}
	result := make(map[string]PeerTrafficStats, len(stats))
	for ip, s := range stats {
		result[ip] = PeerTrafficStats{Bytes: s.Bytes, Packets: s.Packets, Dropped: s.Dropped}
	}
	return result
}

// SetPeerRateLimit adds or updates a per-peer egress rate limit.
func (f *kernelForwarder) SetPeerRateLimit(peerIP string, rate, ceil uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.rateLimiter == nil {
		rl, err := tc.NewRateLimiter(f.ifName)
		if err != nil {
			return fmt.Errorf("create rate limiter: %w", err)
		}
		if err := rl.Start(); err != nil {
			return fmt.Errorf("start rate limiter: %w", err)
		}
		f.rateLimiter = rl
	}
	if err := f.rateLimiter.AddPeer(peerIP, tc.RateLimit{Rate: rate, Ceil: ceil}); err != nil {
		return err
	}
	f.rateLimits[peerIP] = PeerRateLimitInfo{Rate: rate, Ceil: ceil}
	return nil
}

// RemovePeerRateLimit removes a per-peer egress rate limit.
func (f *kernelForwarder) RemovePeerRateLimit(peerIP string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rateLimiter == nil {
		return nil
	}
	if err := f.rateLimiter.RemovePeer(peerIP); err != nil {
		return err
	}
	delete(f.rateLimits, peerIP)
	return nil
}

// PeerRateLimits returns a snapshot of configured per-peer rate limits.
func (f *kernelForwarder) PeerRateLimits() map[string]PeerRateLimitInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.rateLimits) == 0 {
		return nil
	}
	out := make(map[string]PeerRateLimitInfo, len(f.rateLimits))
	for ip, l := range f.rateLimits {
		out[ip] = l
	}
	return out
}

// installNFTForwardRule adds an nftables base chain to allow forwarding traffic
// from and to the same WireGuard interface for the given CIDR.
//
// The chain priority is set to NF_IP_PRI_MANGLE (-150) which runs BEFORE
// iptables-nft's filter chain (priority 0). In nf_tables, an ACCEPT verdict
// terminates all further chain evaluation at the same hook, so our ACCEPT
// prevents iptables-nft's DROP policy from killing forwarded packets.
//
// Equivalent nft command:
//
//	table ip yat_relay {
//	  chain forward {
//	    type filter hook forward priority mangle; policy accept;
//	    iifname "<ifName>" oifname "<ifName>" ip daddr <cidr> accept  /* yat-relay:<ifName> */
//	  }
//	}
//
// Returns the forward rule handle.
func installNFTForwardRule(ifName, cidr string) (fwdHandle uint64, err error) {
	conn, err := nftables.New()
	if err != nil {
		return 0, fmt.Errorf("open nftables: %w", err)
	}

	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nftTableName,
	}
	conn.AddTable(table)

	// --- FORWARD chain: ACCEPT same-interface peer traffic ---
	chainPolicy := nftables.ChainPolicyAccept
	fwdChain := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeFilter,
		Policy:   &chainPolicy,
	})

	_, cidrNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}

	fwdRule := conn.AddRule(&nftables.Rule{
		Table:    table,
		Chain:    fwdChain,
		Exprs:    buildNFTRuleExprs(ifName, cidrNet),
		UserData: []byte(fmt.Sprintf("yat-relay:%s", ifName)),
	})

	if err := conn.Flush(); err != nil {
		return 0, err
	}
	return fwdRule.Handle, nil
}

// cleanupLegacyIPTablesRules removes stale iptables FORWARD rules from the
// default filter table.  These rules were added by the original kernel
// forwarder (before the migration to google/nftables) and are no longer
// managed by the current code.  Leaving them in place causes duplicate
// filtering (the nftables yat_relay table already handles forwarding)
// and may conflict with user-managed iptables rules.
func cleanupLegacyIPTablesRules(ifName, cidr string) {
	// Best-effort: remove the exact rule pattern used by the old code.
	// `iptables -D` succeeds if the rule exists, fails if it doesn't.
	// Loop to remove duplicates (the old code used -I which may have
	// inserted the same rule multiple times across restarts).
	for {
		cmd := exec.Command("iptables", "-D", "FORWARD",
			"-i", ifName, "-o", ifName,
			"-d", cidr, "-j", "ACCEPT")
		if output, err := cmd.CombinedOutput(); err != nil {
			// Rule no longer exists — cleanup done.
			_ = output
			break
		}
		logger.Infof("cleaned up legacy iptables FORWARD rule: iface=%s cidr=%s", ifName, cidr)
	}
}

// cleanupNFTTable removes the entire yat_relay nftables table.
// Called during relay manager shutdown after all forwarders have stopped.
func cleanupNFTTable() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("open nftables: %w", err)
	}
	conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nftTableName,
	})
	return conn.Flush()
}

// removeNFTForwardRule removes the nftables rule installed by installNFTForwardRule.
// It first tries the stored handle; if that fails, it falls back to scanning
// the chain for a matching rule (handles edge restarts where the handle is lost).
func removeNFTForwardRule(ifName, cidr string, fwdHandle uint64) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("open nftables: %w", err)
	}

	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nftTableName,
	}

	// Remove forward ACCEPT rule.
	fwdChain := &nftables.Chain{
		Name:  "forward",
		Table: table,
	}
	if fwdHandle != 0 {
		conn.DelRule(&nftables.Rule{
			Table:  table,
			Chain:  fwdChain,
			Handle: fwdHandle,
		})
		if err := conn.Flush(); err == nil {
			return nil
		}
		// Fall through to scan-based deletion.
		conn2, err2 := nftables.New()
		if err2 != nil {
			return fmt.Errorf("reopen nftables: %w", err2)
		}
		conn = conn2
	}

	// Slow path: scan rules and match by interface name + CIDR.
	rules, err := conn.GetRules(table, fwdChain)
	if err != nil {
		return fmt.Errorf("list nftables rules: %w", err)
	}

	_, cidrNet, _ := net.ParseCIDR(cidr)
	ifNamePadded := ifnameBytes(ifName)

	for _, r := range rules {
		if ruleMatchesForwardRule(r.Exprs, ifNamePadded, cidrNet) {
			conn.DelRule(r)
			return conn.Flush()
		}
	}
	return fmt.Errorf("matching nftables rule not found for %s/%s", ifName, cidr)
}

// buildNFTRuleExprs constructs the nftables expressions for:
//
//	iifname <ifName> oifname <ifName> ip daddr & <mask> == <network> accept
func buildNFTRuleExprs(ifName string, cidr *net.IPNet) []expr.Any {
	ifNamePadded := ifnameBytes(ifName)
	mask := cidrMaskBigEndian(cidr)
	networkAddr := cidr.IP.To4().Mask(cidr.Mask)

	return []expr.Any{
		// meta iifname <ifName>
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifNamePadded},
		// meta oifname <ifName>
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifNamePadded},
		// payload ip daddr (offset 16, len 4 in network header)
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       16,
			Len:          4,
		},
		// bitwise: reg1 = reg1 & mask (CIDR mask matching)
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           mask,
			Xor:            make([]byte, 4),
		},
		// cmp: reg1 == network address
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: networkAddr},
		// verdict accept
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// ruleMatchesForwardRule checks whether a rule's expressions match the pattern
// produced by buildNFTRuleExprs for the given interface and CIDR.
func ruleMatchesForwardRule(exprs []expr.Any, ifNamePadded []byte, cidr *net.IPNet) bool {
	if len(exprs) < 8 {
		return false
	}
	// Check iifname (expr 0=Meta IIFNAME, 1=Cmp ifName)
	meta0, ok0 := exprs[0].(*expr.Meta)
	cmp0, ok0b := exprs[1].(*expr.Cmp)
	if !ok0 || !ok0b || meta0.Key != expr.MetaKeyIIFNAME || !bytes.Equal(cmp0.Data, ifNamePadded) {
		return false
	}
	// Check oifname (expr 2=Meta OIFNAME, 3=Cmp ifName)
	meta1, ok1 := exprs[2].(*expr.Meta)
	cmp1, ok1b := exprs[3].(*expr.Cmp)
	if !ok1 || !ok1b || meta1.Key != expr.MetaKeyOIFNAME || !bytes.Equal(cmp1.Data, ifNamePadded) {
		return false
	}
	// Check payload + bitwise + cmp for CIDR (expr 4=Payload, 5=Bitwise, 6=Cmp)
	_, okP := exprs[4].(*expr.Payload)
	bw, okB := exprs[5].(*expr.Bitwise)
	cmpN, okC := exprs[6].(*expr.Cmp)
	if !okP || !okB || !okC {
		return false
	}
	expectedMask := cidrMaskBigEndian(cidr)
	expectedNet := cidr.IP.To4().Mask(cidr.Mask)
	if !bytes.Equal(bw.Mask, expectedMask) || !bytes.Equal(cmpN.Data, expectedNet) {
		return false
	}
	// Check verdict accept (expr 7)
	v, okV := exprs[7].(*expr.Verdict)
	return okV && v.Kind == expr.VerdictAccept
}

// ifnameBytes returns the interface name padded to IFNAMSIZ (16 bytes)
// with null bytes, as expected by the kernel's nftables meta comparison.
func ifnameBytes(ifName string) []byte {
	b := make([]byte, 16)
	copy(b, ifName)
	return b
}

// cidrMaskBigEndian converts a CIDR mask to a 4-byte big-endian representation
// suitable for nftables Bitwise mask matching.
func cidrMaskBigEndian(cidr *net.IPNet) []byte {
	mask := cidr.Mask
	if len(mask) == 16 {
		mask = mask[12:16] // IPv4-mapped IPv6 → IPv4
	}
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, binary.BigEndian.Uint32(mask))
	return result
}

// installIPTablesForwardRule inserts an iptables FORWARD rule to accept
// same-interface WireGuard traffic for the given CIDR. This is a fallback
// for systems using iptables-legacy where nftables rules have no effect
// on the iptables FORWARD chain policy (e.g. Docker's DROP policy).
//
// Equivalent command:
//
//	iptables -I FORWARD -i <ifName> -o <ifName> -d <cidr> -j ACCEPT
func installIPTablesForwardRule(ifName, cidr string) error {
	cmd := exec.Command("iptables", "-I", "FORWARD",
		"-i", ifName, "-o", ifName,
		"-d", cidr, "-j", "ACCEPT")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables insert FORWARD rule for %s: %s: %w", ifName, string(output), err)
	}
	return nil
}

// removeIPTablesForwardRule removes all iptables FORWARD rules matching
// the given interface and CIDR. Loops to handle duplicates from previous
// runs that may have been inserted multiple times.
func removeIPTablesForwardRule(ifName, cidr string) error {
	for {
		cmd := exec.Command("iptables", "-D", "FORWARD",
			"-i", ifName, "-o", ifName,
			"-d", cidr, "-j", "ACCEPT")
		if _, err := cmd.CombinedOutput(); err != nil {
			break // no more matching rules
		}
	}
	return nil
}

// writeSysctl writes a value to a /proc/sys kernel parameter.
func writeSysctl(key, value string) error {
	path := "/proc/sys/" + key
	return os.WriteFile(path, []byte(value), 0644)
}
