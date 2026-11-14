package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"icool.io/yat/edge/internal/channel/wireguard"
	"icool.io/yat/edge/internal/daemon"
	"icool.io/yat/edge/internal/ipc"
	"icool.io/yat/edge/pkg/config"
)

var networksCmd = &cobra.Command{
	Use:   "networks",
	Short: "Manage WireGuard networks",
	Long:  `Inspect and clean up WireGuard networks stored on the edge: list, show details, list members, and remove`,
}

var networksListCmd = &cobra.Command{
	Use:   "list",
	Short: "List WireGuard networks",
	Long:  `List WireGuard networks stored on this edge (active only; deleted rows are excluded)`,
	RunE:  runNetworksList,
}

var networksInfoCmd = &cobra.Command{
	Use:   "info <network-id>",
	Short: "Show network details",
	Long:  `Display a WireGuard network with its members and peer sessions`,
	Args:  cobra.ExactArgs(1),
	RunE:  runNetworksInfo,
}

var networksMembersCmd = &cobra.Command{
	Use:   "members <network-id>",
	Short: "List members of a network",
	Long:  `List the members (devices) of a WireGuard network`,
	Args:  cobra.ExactArgs(1),
	RunE:  runNetworksMembers,
}

var networksRemoveCmd = &cobra.Command{
	Use:   "remove <network-id>",
	Short: "Delete a WireGuard network",
	Long:  `Delete a WireGuard network and its members/sessions from the edge store`,
	Args:  cobra.ExactArgs(1),
	RunE:  runNetworksRemove,
}

var networksDBPath string
var networksSockFile string

// networksRateLimitCmd manages per-peer rate limits for a running network.
var networksRateLimitCmd = &cobra.Command{
	Use:   "rate-limit <network-id> set|remove|query [peer-ip] [rate] [ceil]",
	Short: "Manage per-peer egress rate limits",
	Long: `Set, remove, or query per-peer egress rate limits on a running WireGuard network.
Rate values are in bytes per second. Requires the edge server to be running.

Examples:
  edge networks rate-limit <net-id> set 10.25.0.2 125000           # 1 Mbps symmetric
  edge networks rate-limit <net-id> set 10.25.0.2 125000 500000    # 1 Mbps rate, 4 Mbps ceil
  edge networks rate-limit <net-id> remove 10.25.0.2
  edge networks rate-limit <net-id> query                          # list all limits
  edge networks rate-limit <net-id> query 10.25.0.2                # query single peer`,
	Args: cobra.RangeArgs(2, 5),
	RunE: runNetworksRateLimit,
}

func init() {
	rootCmd.AddCommand(networksCmd)
	networksCmd.AddCommand(networksListCmd)
	networksCmd.AddCommand(networksInfoCmd)
	networksCmd.AddCommand(networksMembersCmd)
	networksCmd.AddCommand(networksRemoveCmd)
	networksCmd.AddCommand(networksRateLimitCmd)

	networksCmd.PersistentFlags().StringVar(
		&networksDBPath,
		"db",
		"",
		fmt.Sprintf("WireGuard database path (default: %s/wireguard.db)", config.DefaultDataDir()),
	)
	networksCmd.PersistentFlags().StringVar(
		&networksSockFile,
		"sock-file",
		"",
		fmt.Sprintf("IPC socket file (default: %s)", daemon.DefaultSockFile),
	)
}

// getWGStore opens (or locates) the WireGuard SQLite database.
// Resolution order mirrors the tunnel CLI: --db > --data/dataDir > stat candidates > default.
func getWGStore() (wireguard.Storage, error) {
	var dbPath string
	defaultDBPath := filepath.Join(config.DefaultDataDir(), "wireguard.db")

	if networksDBPath != "" {
		dbPath = networksDBPath
	} else if dataDir != "" {
		dbPath = filepath.Join(dataDir, "wireguard.db")
	} else {
		candidates := []string{
			defaultDBPath,
			filepath.Join(os.Getenv("HOME"), ".edge/wireguard.db"),
			"/var/lib/edge/wireguard.db",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				dbPath = c
				break
			}
		}
		if dbPath == "" {
			dbPath = defaultDBPath
		}
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	return wireguard.NewSQLiteStorage(dbPath)
}

// groupMembers indexes members by their network ID.
func groupMembers(members []*wireguard.NetworkMember) map[string][]*wireguard.NetworkMember {
	byNetwork := make(map[string][]*wireguard.NetworkMember)
	for _, m := range members {
		if m == nil {
			continue
		}
		// Defensive: SQLite never persists Online (it is ephemeral and
		// lost on Edge restart).  Reset to Active so the fallback path
		// (Edge not running) shows a consistent state.
		// When the Edge IS running, applyRuntimeMemberStatus overlays
		// the real-time status from the in-memory coordinator via IPC.
		if m.Status == wireguard.MemberStatusOnline {
			m.Status = wireguard.MemberStatusActive
		}
		byNetwork[m.NetworkID] = append(byNetwork[m.NetworkID], m)
	}
	return byNetwork
}

func findNetwork(networks []*wireguard.Network, networkID string) *wireguard.Network {
	for _, n := range networks {
		if n != nil && n.ID == networkID {
			return n
		}
	}
	return nil
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// shortKey truncates a public key for table display.
func shortKey(key string) string {
	if key == "" {
		return "-"
	}
	if len(key) <= 12 {
		return key
	}
	return key[:12] + "…"
}

// memberKeyDisplay 展示成员公钥；代加成员以 clientId 占位时明确标注，避免与真实公钥混淆。
func memberKeyDisplay(m *wireguard.NetworkMember) string {
	if !wireguard.MemberHasRealPublicKey(m) {
		return "(placeholder)"
	}
	return shortKey(m.PublicKey)
}

func memberRoleDisplay(m *wireguard.NetworkMember) string {
	if m != nil && m.IsRelay {
		return "relay"
	}
	return "peer"
}

// memberStateDisplay returns a rich state string for display.
// When the Edge is running, real-time status is overlaid via IPC from the
// current authenticated control sessions (Online/Active/Leaved). When the Edge is not
// running, the status falls back to SQLite (typically Active = "registered").
func memberStateDisplay(m *wireguard.NetworkMember) string {
	if m == nil {
		return "-"
	}
	switch m.Status {
	case wireguard.MemberStatusOnline:
		return "online"
	case wireguard.MemberStatusActive:
		return "registered"
	case wireguard.MemberStatusPending:
		return "pending"
	case wireguard.MemberStatusLeaved:
		return "leaved"
	case wireguard.MemberStatusRemoved:
		return "removed"
	default:
		return "unknown"
	}
}

// formatRateLimit humanizes a rate limit in bytes/sec.
func formatRateLimit(rate, ceil uint64) string {
	formatBps := func(bps uint64) string {
		switch {
		case bps >= 125000000: // 1 Gbps
			return fmt.Sprintf("%.1f Gbps", float64(bps)/125000000)
		case bps >= 125000: // 1 Mbps
			return fmt.Sprintf("%.1f Mbps", float64(bps)/125000)
		case bps >= 1250: // 10 Kbps
			return fmt.Sprintf("%.1f Kbps", float64(bps)/1250)
		default:
			return fmt.Sprintf("%d B/s", bps)
		}
	}
	if ceil == 0 || ceil == rate {
		return formatBps(rate)
	}
	return fmt.Sprintf("%s/%s", formatBps(rate), formatBps(ceil))
}

// extractRateLimits parses rate_limits from runtime data.
func extractRateLimits(runtime map[string]interface{}) map[string]struct{ rate, ceil uint64 } {
	if runtime == nil {
		return nil
	}
	rlRaw, ok := runtime["rate_limits"].(map[string]interface{})
	if !ok || len(rlRaw) == 0 {
		return nil
	}
	result := make(map[string]struct{ rate, ceil uint64 }, len(rlRaw))
	for ip, v := range rlRaw {
		if m, ok := v.(map[string]interface{}); ok {
			rate := uint64(0)
			ceil := uint64(0)
			if rv, ok := m["Rate"].(float64); ok {
				rate = uint64(rv)
			}
			if cv, ok := m["Ceil"].(float64); ok {
				ceil = uint64(cv)
			}
			result[ip] = struct{ rate, ceil uint64 }{rate, ceil}
		}
	}
	return result
}

func runNetworksList(cmd *cobra.Command, args []string) error {
	store, err := getWGStore()
	if err != nil {
		return err
	}
	defer store.Close()

	snap, err := store.LoadSnapshot(context.Background())
	if err != nil {
		return fmt.Errorf("load networks: %w", err)
	}

	if len(snap.Networks) == 0 {
		fmt.Println("No WireGuard networks found")
		return nil
	}

	membersByNetwork := groupMembers(snap.Members)

	networks := append([]*wireguard.Network(nil), snap.Networks...)
	sort.Slice(networks, func(i, j int) bool {
		return networks[i].UpdatedAt.After(networks[j].UpdatedAt)
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NETWORK ID\tNAME\tCIDR\tRELAY MODE\tMEMBERS\tCOORDINATOR\tUPDATED")
	fmt.Fprintln(w, "----------\t----\t----\t----------\t-------\t-----------\t-------")
	for _, n := range networks {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			n.ID,
			dashIfEmpty(n.Name),
			dashIfEmpty(n.CIDR),
			wireguard.RelayModeText(n.RelayMode),
			len(membersByNetwork[n.ID]),
			dashIfEmpty(n.CoordinatorEdgeID),
			n.UpdatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	return w.Flush()
}

// queryNetworkRuntime queries the running edge via IPC for runtime info.
// Returns nil map if the edge is not running or IPC fails.
func queryNetworkRuntime(networkID string) map[string]interface{} {
	sockPath := networksSockFile
	if sockPath == "" {
		sockPath = daemon.DefaultSockFile
	}
	client := ipc.NewClient(sockPath)
	resp, err := client.SendCommand("network_info", map[string]interface{}{
		"network_id": networkID,
	})
	if err != nil || !resp.Success {
		return nil
	}
	return resp.Data
}

// queryNetworkMembers queries the running edge via IPC for the real-time
// member list. Client Online status is projected from current authenticated
// control sessions and is never persisted in SQLite.
func queryNetworkMembers(networkID string) []map[string]interface{} {
	sockPath := networksSockFile
	if sockPath == "" {
		sockPath = daemon.DefaultSockFile
	}
	client := ipc.NewClient(sockPath)
	resp, err := client.SendCommand("network_members", map[string]interface{}{
		"network_id": networkID,
	})
	if err != nil || !resp.Success {
		return nil
	}
	raw, ok := resp.Data["members"]
	if !ok {
		return nil
	}
	members, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	result := make([]map[string]interface{}, 0, len(members))
	for _, item := range members {
		if m, ok := item.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	return result
}

// applyRuntimeMemberStatus overlays real-time member state (queried via IPC
// from the running Edge) onto the SQLite-loaded member structs. When the Edge
// is not running or IPC is unavailable, the original SQLite status is kept.
// The in-memory coordinator tracks ephemeral fields (Online status, observed
// endpoint, LAN endpoint) which SQLite never persists, so the CLI must overlay
// all three from the live process to avoid showing stale data.
func applyRuntimeMemberStatus(members []*wireguard.NetworkMember, runtime []map[string]interface{}) {
	if len(runtime) == 0 {
		return
	}
	type runtimeOverlay struct {
		status      wireguard.MemberStatus
		endpoint    string
		lanEndpoint string
	}
	overlayByID := make(map[string]runtimeOverlay, len(runtime))
	for _, rm := range runtime {
		id, _ := rm["member_id"].(string)
		statusFloat, _ := rm["status"].(float64)
		endpoint, _ := rm["endpoint"].(string)
		lanEndpoint, _ := rm["lan_endpoint"].(string)
		if id != "" {
			overlayByID[id] = runtimeOverlay{
				status:      wireguard.MemberStatus(int(statusFloat)),
				endpoint:    endpoint,
				lanEndpoint: lanEndpoint,
			}
		}
	}
	for _, m := range members {
		if ov, ok := overlayByID[m.ID]; ok {
			m.Status = ov.status
			m.Endpoint = ov.endpoint
			m.LANEndpoint = ov.lanEndpoint
		}
	}
}

// formatBytes humanizes a byte count.
func formatBytes(b uint64) string {
	const (
		kb = 1000
		mb = 1000 * kb
		gb = 1000 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func runNetworksInfo(cmd *cobra.Command, args []string) error {
	networkID := args[0]

	store, err := getWGStore()
	if err != nil {
		return err
	}
	defer store.Close()

	snap, err := store.LoadSnapshot(context.Background())
	if err != nil {
		return fmt.Errorf("load networks: %w", err)
	}

	n := findNetwork(snap.Networks, networkID)
	if n == nil {
		return fmt.Errorf("network not found: %s", networkID)
	}

	members := groupMembers(snap.Members)[networkID]
	runtime := queryNetworkRuntime(networkID)

	// Overlay real-time member status from the running Edge so the CLI
	// shows accurate Online/Active/Leaved state instead of always "registered".
	runtimeMembers := queryNetworkMembers(networkID)
	applyRuntimeMemberStatus(members, runtimeMembers)
	if runtimeMembers == nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "Live member state unavailable; STATE shows registration data from SQLite.")
	}

	fmt.Printf("WireGuard Network:\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Network ID:    %s\n", n.ID)
	fmt.Printf("Name:          %s\n", dashIfEmpty(n.Name))
	fmt.Printf("CIDR:          %s\n", dashIfEmpty(n.CIDR))
	fmt.Printf("Relay Mode:    %s\n", wireguard.RelayModeText(n.RelayMode))
	fmt.Printf("Coordinator:   %s\n", dashIfEmpty(n.CoordinatorEdgeID))
	fmt.Printf("Members:       %d\n", len(members))
	fmt.Printf("Sessions:      0 (ephemeral — not persisted)\n")
	fmt.Printf("Created At:    %s\n", n.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Updated At:    %s\n", n.UpdatedAt.Format("2006-01-02 15:04:05"))

	// Device info: find the relay member (this edge's representation).
	for _, m := range members {
		if m.IsRelay {
			fmt.Printf("\nDevice (relay node):\n")
			fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
			fmt.Printf("Device ID:     %s\n", m.ID)
			fmt.Printf("Hostname:      %s\n", dashIfEmpty(m.HostName))
			fmt.Printf("Assigned IP:   %s\n", dashIfEmpty(m.IP))
			fmt.Printf("Public Key:    %s\n", memberKeyDisplay(m))
			break
		}
	}

	if runtime != nil {
		fmt.Printf("\nRuntime (live):\n")
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("Interface:     %s\n", dashIfEmpty(fmt.Sprintf("%v", runtime["interface_name"])))
		fmt.Printf("Strategy:      %s\n", dashIfEmpty(fmt.Sprintf("%v", runtime["forwarder_strategy"])))
		if rtID, ok := runtime["route_table_id"].(float64); ok && rtID > 0 {
			fmt.Printf("Route Table:   %.0f (allocated)\n", rtID)
		} else {
			fmt.Printf("Route Table:   - (not allocated)\n")
		}
		if fwd, ok := runtime["forwarded"].(float64); ok {
			fmt.Printf("Forwarded:     %.0f pkts\n", fwd)
		}
		if drp, ok := runtime["dropped"].(float64); ok {
			fmt.Printf("Dropped:       %.0f pkts\n", drp)
		}
		// Show configured rate limits summary.
		if rl := extractRateLimits(runtime); len(rl) > 0 {
			fmt.Printf("Rate Limits:   %d peer(s) configured\n", len(rl))
			for ip, l := range rl {
				fmt.Printf("               %s → %s\n", ip, formatRateLimit(l.rate, l.ceil))
			}
		}
	} else {
		fmt.Printf("\nRuntime:       (edge not running or IPC unavailable)\n")
	}

	if len(members) > 0 {
		rateLimits := extractRateLimits(runtime)
		fmt.Printf("\nMembers:\n")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "MEMBER ID\tHOSTNAME\tROLE\tIP\tSTATE\tPUBLIC KEY\tRATE LIMIT\tOBSERVED ENDPOINT\tLAN ENDPOINT")
		fmt.Fprintln(w, "---------\t---------\t----\t--\t-----\t----------\t----------\t-----------------\t------------")
		for _, m := range members {
			rlDisplay := "-"
			if rateLimits != nil {
				if l, ok := rateLimits[m.IP]; ok {
					rlDisplay = formatRateLimit(l.rate, l.ceil)
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				m.ID,
				dashIfEmpty(m.HostName),
				memberRoleDisplay(m),
				dashIfEmpty(m.IP),
				memberStateDisplay(m),
				memberKeyDisplay(m),
				rlDisplay,
				dashIfEmpty(m.Endpoint),
				dashIfEmpty(m.LANEndpoint),
			)
		}
		if err := w.Flush(); err != nil {
			return err
		}

		// Per-peer traffic stats (from runtime).
		if runtime != nil {
			if peerStatsRaw, ok := runtime["peer_stats"].(map[string]interface{}); ok && len(peerStatsRaw) > 0 {
				fmt.Printf("\nPer-Peer Traffic (live):\n")
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "PEER IP\tBYTES\tPACKETS\tDROPPED")
				fmt.Fprintln(w, "-------\t-----\t-------\t-------")
				ips := make([]string, 0, len(peerStatsRaw))
				for ip := range peerStatsRaw {
					ips = append(ips, ip)
				}
				sort.Strings(ips)
				for _, ip := range ips {
					ps, ok := peerStatsRaw[ip].(map[string]interface{})
					if !ok {
						continue
					}
					bytes := uint64(0)
					packets := uint64(0)
					dropped := uint64(0)
					if v, ok := ps["Bytes"].(float64); ok {
						bytes = uint64(v)
					}
					if v, ok := ps["Packets"].(float64); ok {
						packets = uint64(v)
					}
					if v, ok := ps["Dropped"].(float64); ok {
						dropped = uint64(v)
					}
					fmt.Fprintf(w, "%s\t%s\t%d\t%d\n", ip, formatBytes(bytes), packets, dropped)
				}
				_ = w.Flush()
			}
		}
	}

	// Sessions are ephemeral — not displayed from storage.

	// Same-NAT analysis: group non-relay members by observed public IP.
	nonRelayMembers := make([]*wireguard.NetworkMember, 0)
	for _, m := range members {
		if !m.IsRelay && wireguard.MemberHasRealPublicKey(m) && m.Endpoint != "" {
			nonRelayMembers = append(nonRelayMembers, m)
		}
	}
	byPublicIP := make(map[string][]*wireguard.NetworkMember)
	for _, m := range nonRelayMembers {
		host, _, err := net.SplitHostPort(m.Endpoint)
		if err != nil || host == "" {
			continue
		}
		byPublicIP[host] = append(byPublicIP[host], m)
	}
	var sameNATGroups [][]*wireguard.NetworkMember
	for _, group := range byPublicIP {
		if len(group) >= 2 {
			sameNATGroups = append(sameNATGroups, group)
		}
	}
	if len(sameNATGroups) > 0 {
		fmt.Printf("\nSame-NAT Peers (same observed public IP):\n")
		for _, group := range sameNATGroups {
			host, _, _ := net.SplitHostPort(group[0].Endpoint)
			peerDescs := make([]string, 0, len(group))
			for _, m := range group {
				peerDescs = append(peerDescs, fmt.Sprintf("%s (%s)", shortKey(m.PublicKey), dashIfEmpty(m.HostName)))
			}
			fmt.Printf("  Public IP %s: %s\n", host, strings.Join(peerDescs, ", "))
		}
		fmt.Printf("  → LAN direct path optimization active\n")
	} else {
		fmt.Printf("\nSame-NAT Peers: none detected\n")
	}

	return nil
}

func runNetworksMembers(cmd *cobra.Command, args []string) error {
	networkID := args[0]

	store, err := getWGStore()
	if err != nil {
		return err
	}
	defer store.Close()

	snap, err := store.LoadSnapshot(context.Background())
	if err != nil {
		return fmt.Errorf("load networks: %w", err)
	}

	if findNetwork(snap.Networks, networkID) == nil {
		return fmt.Errorf("network not found: %s", networkID)
	}

	members := groupMembers(snap.Members)[networkID]

	// Overlay real-time member status from the running Edge.
	runtimeMembers := queryNetworkMembers(networkID)
	applyRuntimeMemberStatus(members, runtimeMembers)
	if runtimeMembers == nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "Live member state unavailable; STATE shows registration data from SQLite.")
	}

	if len(members) == 0 {
		fmt.Printf("No members found for network %s\n", networkID)
		return nil
	}

	runtime := queryNetworkRuntime(networkID)
	rateLimits := extractRateLimits(runtime)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "MEMBER ID\tCLIENT ID\tROLE\tIP\tSTATE\tPUBLIC KEY\tRATE LIMIT\tOBSERVED ENDPOINT\tLAN ENDPOINT")
	fmt.Fprintln(w, "---------\t---------\t----\t--\t-----\t----------\t----------\t-----------------\t------------")
	for _, m := range members {
		rlDisplay := "-"
		if rateLimits != nil {
			if l, ok := rateLimits[m.IP]; ok {
				rlDisplay = formatRateLimit(l.rate, l.ceil)
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			m.ID,
			dashIfEmpty(m.ClientID),
			memberRoleDisplay(m),
			dashIfEmpty(m.IP),
			memberStateDisplay(m),
			memberKeyDisplay(m),
			rlDisplay,
			dashIfEmpty(m.Endpoint),
			dashIfEmpty(m.LANEndpoint),
		)
	}
	return w.Flush()
}

func runNetworksRemove(cmd *cobra.Command, args []string) error {
	networkID := args[0]

	store, err := getWGStore()
	if err != nil {
		return err
	}
	defer store.Close()

	ctx := context.Background()
	snap, err := store.LoadSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("load networks: %w", err)
	}

	n := findNetwork(snap.Networks, networkID)
	if n == nil {
		return fmt.Errorf("network not found: %s", networkID)
	}

	// DeleteNetwork 不级联，逐个清理成员避免遗留孤儿行。
	members := groupMembers(snap.Members)[networkID]
	for _, m := range members {
		if err := store.DeleteMember(ctx, m.ID); err != nil {
			return fmt.Errorf("delete member %s: %w", m.ID, err)
		}
	}
	if err := store.DeleteNetwork(ctx, networkID); err != nil {
		return fmt.Errorf("remove network: %w", err)
	}

	fmt.Printf("✓ Network removed: %s (%s) — %d member(s) cleaned\n",
		networkID, dashIfEmpty(n.Name), len(members))
	return nil
}

func runNetworksRateLimit(cmd *cobra.Command, args []string) error {
	networkID := args[0]
	action := args[1]

	sockPath := networksSockFile
	if sockPath == "" {
		sockPath = daemon.DefaultSockFile
	}
	client := ipc.NewClient(sockPath)

	switch action {
	case "set":
		if len(args) < 4 {
			return fmt.Errorf("usage: rate-limit <network-id> set <peer-ip> <rate> [ceil]")
		}
		peerIP := args[2]
		rate, err := strconv.ParseUint(args[3], 10, 64)
		if err != nil || rate == 0 {
			return fmt.Errorf("rate must be a positive integer (bytes/sec)")
		}
		ceil := rate
		if len(args) >= 5 {
			ceil, err = strconv.ParseUint(args[4], 10, 64)
			if err != nil || ceil == 0 {
				return fmt.Errorf("ceil must be a positive integer (bytes/sec)")
			}
		}
		resp, err := client.SendCommand("network_rate_limit", map[string]interface{}{
			"network_id": networkID,
			"action":     "set",
			"peer_ip":    peerIP,
			"rate":       rate,
			"ceil":       ceil,
		})
		if err != nil {
			return fmt.Errorf("IPC failed: %w (is edge server running?)", err)
		}
		if !resp.Success {
			return fmt.Errorf("%s", resp.Message)
		}
		fmt.Printf("✓ Rate limit set: %s → %s\n", peerIP, formatRateLimit(rate, ceil))
		return nil

	case "remove":
		if len(args) < 3 {
			return fmt.Errorf("usage: rate-limit <network-id> remove <peer-ip>")
		}
		peerIP := args[2]
		resp, err := client.SendCommand("network_rate_limit", map[string]interface{}{
			"network_id": networkID,
			"action":     "remove",
			"peer_ip":    peerIP,
		})
		if err != nil {
			return fmt.Errorf("IPC failed: %w (is edge server running?)", err)
		}
		if !resp.Success {
			return fmt.Errorf("%s", resp.Message)
		}
		fmt.Printf("✓ Rate limit removed: %s\n", peerIP)
		return nil

	case "query":
		params := map[string]interface{}{
			"network_id": networkID,
			"action":     "query",
		}
		if len(args) >= 3 {
			params["peer_ip"] = args[2]
		}
		resp, err := client.SendCommand("network_rate_limit", params)
		if err != nil {
			return fmt.Errorf("IPC failed: %w (is edge server running?)", err)
		}
		if !resp.Success {
			return fmt.Errorf("%s", resp.Message)
		}
		return printRateLimitQuery(resp.Data)

	default:
		return fmt.Errorf("action must be 'set', 'remove', or 'query'")
	}
}

func printRateLimitQuery(data interface{}) error {
	m, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected response format")
	}
	networkID, _ := m["network_id"].(string)

	// Single peer query.
	if peerIP, ok := m["peer_ip"].(string); ok {
		configured, _ := m["configured"].(bool)
		if !configured {
			fmt.Printf("Network %s: peer %s has no rate limit configured\n", networkID, peerIP)
			return nil
		}
		rate, _ := m["rate"].(float64)
		ceil, _ := m["ceil"].(float64)
		fmt.Printf("Network %s: peer %s → %s\n", networkID, peerIP, formatRateLimit(uint64(rate), uint64(ceil)))
		return nil
	}

	// Network-wide query.
	rateLimitsRaw, _ := m["rate_limits"].(map[string]interface{})
	if len(rateLimitsRaw) == 0 {
		fmt.Printf("Network %s: no rate limits configured\n", networkID)
		return nil
	}
	fmt.Printf("Network %s rate limits:\n", networkID)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PEER IP\tRATE\tCEIL")
	// Sort by IP for stable output.
	ips := make([]string, 0, len(rateLimitsRaw))
	for ip := range rateLimitsRaw {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		limitRaw, _ := rateLimitsRaw[ip].(map[string]interface{})
		rate, _ := limitRaw["Rate"].(float64)
		ceil, _ := limitRaw["Ceil"].(float64)
		fmt.Fprintf(w, "%s\t%s\t%s\n", ip, formatBytesPerSec(uint64(rate)), formatBytesPerSec(uint64(ceil)))
	}
	w.Flush()
	return nil
}

func formatBytesPerSec(bps uint64) string {
	const (
		kb = 1000
		mb = 1000 * kb
	)
	switch {
	case bps >= mb:
		return fmt.Sprintf("%.1f MB/s (%.1f Mbps)", float64(bps)/float64(mb), float64(bps)*8/float64(mb))
	case bps >= kb:
		return fmt.Sprintf("%.1f KB/s (%.1f Kbps)", float64(bps)/float64(kb), float64(bps)*8/float64(kb))
	default:
		return fmt.Sprintf("%d B/s (%d bps)", bps, bps*8)
	}
}
