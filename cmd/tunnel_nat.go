package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"icool.io/yat/edge/internal/channel"
	"icool.io/yat/edge/internal/channel/ice"
	"icool.io/yat/edge/pkg/config"
)

var tunnelNATCmd = &cobra.Command{
	Use:   "nat [tunnel-id]",
	Short: "Show NAT/ICE stats as terminal charts",
	Long:  `Render NAT and ICE hole-punching metrics from runtime status.json as ASCII charts`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runTunnelNAT,
}

var (
	natStatusFile string
	natWatch      bool
	natInterval   time.Duration
	natBarWidth   int
)

func init() {
	tunnelCmd.AddCommand(tunnelNATCmd)
	tunnelNATCmd.Flags().StringVar(
		&natStatusFile,
		"status-file",
		"",
		"status json path (default: <data-dir>/status.json)",
	)
	tunnelNATCmd.Flags().BoolVarP(&natWatch, "watch", "w", false, "watch mode (refresh chart continuously)")
	tunnelNATCmd.Flags().DurationVar(&natInterval, "interval", 2*time.Second, "watch refresh interval")
	tunnelNATCmd.Flags().IntVar(&natBarWidth, "width", 36, "bar width for charts")
}

func runTunnelNAT(cmd *cobra.Command, args []string) error {
	filterTunnelID := ""
	if len(args) > 0 {
		filterTunnelID = strings.TrimSpace(args[0])
	}
	if natBarWidth < 10 {
		natBarWidth = 10
	}
	if natInterval < 500*time.Millisecond {
		natInterval = 500 * time.Millisecond
	}

	render := func() error {
		statusPath := resolveStatusPath()
		status, err := loadEdgeStatus(statusPath)
		if err != nil {
			return err
		}
		printNATChart(status, filterTunnelID, natBarWidth)
		return nil
	}

	if !natWatch {
		return render()
	}

	for {
		fmt.Print("\033[H\033[2J")
		if err := render(); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
		time.Sleep(natInterval)
	}
}

func resolveStatusPath() string {
	if strings.TrimSpace(natStatusFile) != "" {
		return strings.TrimSpace(natStatusFile)
	}
	dir := strings.TrimSpace(dataDir)
	if dir == "" {
		dir = config.DefaultDataDir()
	}
	return filepath.Join(dir, "status.json")
}

func loadEdgeStatus(path string) (*channel.EdgeServiceStatus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read status file %s: %w", path, err)
	}
	var status channel.EdgeServiceStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("parse status file %s: %w", path, err)
	}
	return &status, nil
}

func printNATChart(status *channel.EdgeServiceStatus, tunnelID string, barWidth int) {
	fmt.Printf("NAT / ICE Dashboard  %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if status == nil || status.ICE == nil || status.ICEStats == nil {
		fmt.Println("No ICE runtime data in status.json")
		return
	}

	sessions := filterSessions(status.ICE.Sessions, tunnelID)
	if tunnelID != "" {
		fmt.Printf("Edge: %s  TunnelFilter: %s\n", status.EdgeID, tunnelID)
		fmt.Printf("Filtered sessions: %d (global active=%d, global total_seen=%d)\n", len(sessions), status.ICE.ActiveCount, status.ICE.TotalCount)
	} else {
		fmt.Printf("Edge: %s  TunnelFilter: %s\n", status.EdgeID, valueOrAll(tunnelID))
		fmt.Printf("Sessions: %d (active=%d, total_seen=%d)\n", len(sessions), status.ICE.ActiveCount, status.ICE.TotalCount)
	}
	fmt.Printf("Punch: attempts=%d success=%d fail=%d avg_latency=%.1fms avg_attempts_sent=%.2f samples=%d\n",
		status.ICEStats.PunchAttempts,
		status.ICEStats.PunchSuccesses,
		status.ICEStats.PunchFailures,
		status.ICEStats.AvgPunchLatency,
		status.ICEStats.AvgAttemptsSent,
		status.ICEStats.AttemptsSamples,
	)
	fmt.Println()

	natCounts := map[string]int{}
	strategyCounts := map[string]int{}
	stateCounts := map[string]int{}
	pairCounts := map[string]int{}

	for _, s := range sessions {
		pub := normalizeBucket(string(s.PubNAT), "unknown")
		con := normalizeBucket(string(s.ConNAT), "unknown")
		natCounts[pub]++
		natCounts[con]++

		strategy := normalizeBucket(string(s.Strategy), "unknown")
		strategyCounts[strategy]++

		state := normalizeBucket(string(s.State), "unknown")
		stateCounts[state]++

		pairKey := fmt.Sprintf("%s -> %s", pub, con)
		pairCounts[pairKey]++
	}

	printCountChart("NAT Type Distribution (endpoint-level)", natCounts, barWidth)
	printCountChart("Punch Strategy Distribution (session-level)", strategyCounts, barWidth)
	printCountChart("ICE State Distribution (session-level)", stateCounts, barWidth)
	printTopPairs("NAT Pair Topology", pairCounts, 8, barWidth)
}

func filterSessions(in []ice.SessionSnapshot, tunnelID string) []ice.SessionSnapshot {
	if strings.TrimSpace(tunnelID) == "" {
		return in
	}
	out := make([]ice.SessionSnapshot, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s.TunnelID) == tunnelID {
			out = append(out, s)
		}
	}
	return out
}

func valueOrAll(v string) string {
	if strings.TrimSpace(v) == "" {
		return "(all)"
	}
	return v
}

func normalizeBucket(v, fallback string) string {
	trimmed := strings.TrimSpace(strings.ToLower(v))
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func printCountChart(title string, counts map[string]int, width int) {
	fmt.Println(title)
	if len(counts) == 0 {
		fmt.Println("  (no data)")
		fmt.Println()
		return
	}

	type item struct {
		name  string
		count int
	}
	items := make([]item, 0, len(counts))
	maxCount := 0
	for name, count := range counts {
		items = append(items, item{name: name, count: count})
		if count > maxCount {
			maxCount = count
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].name < items[j].name
		}
		return items[i].count > items[j].count
	})

	for _, it := range items {
		barLen := 0
		if maxCount > 0 {
			barLen = int(float64(it.count) / float64(maxCount) * float64(width))
		}
		if barLen == 0 && it.count > 0 {
			barLen = 1
		}
		fmt.Printf("  %-22s | %-*s %4d\n", it.name, width, strings.Repeat("#", barLen), it.count)
	}
	fmt.Println()
}

func printTopPairs(title string, counts map[string]int, topN, width int) {
	fmt.Println(title)
	if len(counts) == 0 {
		fmt.Println("  (no data)")
		fmt.Println()
		return
	}

	type item struct {
		name  string
		count int
	}
	items := make([]item, 0, len(counts))
	maxCount := 0
	for name, count := range counts {
		items = append(items, item{name: name, count: count})
		if count > maxCount {
			maxCount = count
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].name < items[j].name
		}
		return items[i].count > items[j].count
	})
	if len(items) > topN {
		items = items[:topN]
	}
	for _, it := range items {
		barLen := 0
		if maxCount > 0 {
			barLen = int(float64(it.count) / float64(maxCount) * float64(width))
		}
		if barLen == 0 && it.count > 0 {
			barLen = 1
		}
		fmt.Printf("  %-30s | %-*s %4d\n", it.name, width, strings.Repeat("#", barLen), it.count)
	}
	fmt.Println()
}
