package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"icool.io/yat/edge/internal/channel"
	"icool.io/yat/edge/pkg/config"
)

var tunnelCmd = &cobra.Command{
	Use:   "tunnel",
	Short: "Manage tunnel definitions",
	Long:  `Manage tunnel definitions stored on the edge: list, inspect, remove, and clean up`,
}

var tunnelListCmd = &cobra.Command{
	Use:   "list",
	Short: "List tunnel definitions",
	Long:  `List tunnel definitions (active by default; use --all to include deleted)`,
	RunE:  runTunnelList,
}

var tunnelInfoCmd = &cobra.Command{
	Use:   "info <tunnel-id>",
	Short: "Show tunnel details",
	Long:  `Display detailed information about a specific tunnel definition`,
	Args:  cobra.ExactArgs(1),
	RunE:  runTunnelInfo,
}

var tunnelRemoveCmd = &cobra.Command{
	Use:   "remove <tunnel-id>",
	Short: "Soft-delete a tunnel definition",
	Long:  `Mark a tunnel definition as deleted (soft delete)`,
	Args:  cobra.ExactArgs(1),
	RunE:  runTunnelRemove,
}

var tunnelCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Purge deleted tunnel definitions",
	Long:  `Permanently remove soft-deleted tunnel definitions older than N days`,
	RunE:  runTunnelClean,
}

var (
	tunnelDBPath    string
	tunnelEdgeID    string
	tunnelOwnerID   string
	tunnelListAll   bool
	tunnelCleanDays int
)

func init() {
	rootCmd.AddCommand(tunnelCmd)
	tunnelCmd.AddCommand(tunnelListCmd)
	tunnelCmd.AddCommand(tunnelInfoCmd)
	tunnelCmd.AddCommand(tunnelRemoveCmd)
	tunnelCmd.AddCommand(tunnelCleanCmd)

	tunnelCmd.PersistentFlags().StringVar(
		&tunnelDBPath,
		"db",
		"",
		fmt.Sprintf("Tunnel database path (default: %s/tunnels.db)", config.DefaultDataDir()),
	)
	tunnelCmd.PersistentFlags().StringVar(
		&tunnelEdgeID,
		"edge-id",
		"",
		"Edge ID (auto-detected from data directory if not specified)",
	)
	tunnelCmd.PersistentFlags().StringVar(
		&tunnelOwnerID,
		"owner",
		"",
		"Owner user ID (required when tunnel ID exists under multiple owners)",
	)
	tunnelListCmd.Flags().BoolVar(&tunnelListAll, "all", false, "Show all tunnels including deleted")
	tunnelCleanCmd.Flags().IntVar(&tunnelCleanDays, "days", 7, "Purge deleted tunnels older than N days")
}

// getTunnelStore opens (or locates) the tunnel definitions SQLite database.
func getTunnelStore() (*channel.TunnelDefinitionStore, error) {
	var dbPath string
	defaultDBPath := filepath.Join(config.DefaultDataDir(), "tunnels.db")

	if tunnelDBPath != "" {
		dbPath = tunnelDBPath
	} else if dataDir != "" {
		dbPath = filepath.Join(dataDir, "tunnels.db")
	} else {
		candidates := []string{
			defaultDBPath,
			filepath.Join(os.Getenv("HOME"), ".yat/edge/tunnels.db"),
			"/var/lib/yat/edge/tunnels.db",
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

	return channel.NewTunnelDefinitionStore(dbPath)
}

// resolveEdgeID returns the edge ID to use for queries.
// Priority: --edge-id flag > auto-detect from data dir.
func resolveEdgeID() (string, error) {
	if tunnelEdgeID != "" {
		return tunnelEdgeID, nil
	}

	dir := config.DefaultDataDir()
	if dataDir != "" {
		dir = dataDir
	}

	id, err := config.LoadEdgeID(dir)
	if err != nil {
		return "", fmt.Errorf("cannot determine edge ID (use --edge-id flag): %w", err)
	}
	return id, nil
}

func tunnelStateName(rec *channel.TunnelDefinitionRecord) string {
	if rec.DeletedAt != nil {
		return "deleted"
	}
	return rec.State
}

func runTunnelList(cmd *cobra.Command, args []string) error {
	store, err := getTunnelStore()
	if err != nil {
		return err
	}
	defer store.Close()

	edgeID, err := resolveEdgeID()
	if err != nil {
		return err
	}

	ctx := context.Background()
	tunnels, err := store.ListByEdge(ctx, edgeID, tunnelListAll)
	if err != nil {
		return fmt.Errorf("list tunnels: %w", err)
	}

	if len(tunnels) == 0 {
		if tunnelListAll {
			fmt.Println("No tunnel definitions found")
		} else {
			fmt.Println("No active tunnel definitions found (use --all to show deleted)")
		}
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TUNNEL ID\tNAME\tPROTOCOL\tSTATE\tREMOTE URL\tAPP ID\tUPDATED")
	fmt.Fprintln(w, "---------\t----\t--------\t-----\t----------\t------\t-------")
	for _, t := range tunnels {
		remoteUrl := channel.ResolveTunnelRemoteURL(t.RemoteURL, t.RuntimeJSON)
		if remoteUrl == "" {
			remoteUrl = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			t.TunnelID,
			t.Name,
			t.Protocol,
			tunnelStateName(t),
			remoteUrl,
			t.AppID,
			t.UpdatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	return w.Flush()
}

func runTunnelInfo(cmd *cobra.Command, args []string) error {
	tunnelID := args[0]

	store, err := getTunnelStore()
	if err != nil {
		return err
	}
	defer store.Close()

	edgeID, err := resolveEdgeID()
	if err != nil {
		return err
	}

	ctx := context.Background()
	ownerUserID, err := resolveTunnelOwnerForQuery(ctx, store, edgeID, tunnelID, tunnelOwnerID)
	if err != nil {
		return err
	}
	t, err := store.Get(ctx, ownerUserID, edgeID, tunnelID)
	if err != nil {
		return fmt.Errorf("get tunnel: %w", err)
	}
	if t == nil {
		return fmt.Errorf("tunnel not found: %s", tunnelID)
	}

	fmt.Printf("Tunnel Definition:\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Tunnel ID:    %s\n", t.TunnelID)
	fmt.Printf("Edge ID:      %s\n", t.EdgeID)
	fmt.Printf("Name:         %s\n", t.Name)
	fmt.Printf("App ID:       %s\n", t.AppID)
	fmt.Printf("Protocol:     %s\n", t.Protocol)
	fmt.Printf("State:        %s\n", tunnelStateName(t))
	remoteUrl := channel.ResolveTunnelRemoteURL(t.RemoteURL, t.RuntimeJSON)
	if remoteUrl == "" {
		remoteUrl = "-"
	}
	fmt.Printf("Remote URL:   %s\n", remoteUrl)
	fmt.Printf("Version:      %d\n", t.Version)
	fmt.Printf("Revision:     %d\n", t.Revision)
	fmt.Printf("Owner:        %s\n", t.OwnerUserID)
	fmt.Printf("Created At:   %s\n", t.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Updated At:   %s\n", t.UpdatedAt.Format("2006-01-02 15:04:05"))
	if t.DeletedAt != nil {
		fmt.Printf("Deleted At:   %s\n", t.DeletedAt.Format("2006-01-02 15:04:05"))
	}

	// 展示 JSON 字段（格式化输出）
	if t.IntentJSON != "" && t.IntentJSON != "{}" {
		fmt.Printf("\nIntent:\n%s\n", prettyJSON(t.IntentJSON))
	}
	if t.ConfigJSON != "" && t.ConfigJSON != "{}" {
		fmt.Printf("\nConfig:\n%s\n", prettyJSON(t.ConfigJSON))
	}
	if t.RuntimeJSON != "" && t.RuntimeJSON != "{}" {
		fmt.Printf("\nRuntime:\n%s\n", prettyJSON(t.RuntimeJSON))
	}

	return nil
}

func runTunnelRemove(cmd *cobra.Command, args []string) error {
	tunnelID := args[0]

	store, err := getTunnelStore()
	if err != nil {
		return err
	}
	defer store.Close()

	edgeID, err := resolveEdgeID()
	if err != nil {
		return err
	}

	ctx := context.Background()
	ownerUserID, err := resolveTunnelOwnerForQuery(ctx, store, edgeID, tunnelID, tunnelOwnerID)
	if err != nil {
		return err
	}

	// 确认存在
	t, err := store.Get(ctx, ownerUserID, edgeID, tunnelID)
	if err != nil {
		return fmt.Errorf("get tunnel: %w", err)
	}
	if t == nil {
		return fmt.Errorf("tunnel not found: %s", tunnelID)
	}
	if t.DeletedAt != nil {
		fmt.Printf("Tunnel %s is already deleted\n", tunnelID)
		return nil
	}

	changed, err := store.SoftDelete(ctx, ownerUserID, edgeID, tunnelID, 0, "", "")
	if err != nil {
		return fmt.Errorf("remove tunnel: %w", err)
	}
	if changed {
		fmt.Printf("✓ Tunnel removed: %s (%s)\n", tunnelID, t.Name)
	} else {
		fmt.Printf("Tunnel %s was not modified\n", tunnelID)
	}
	return nil
}

func runTunnelClean(cmd *cobra.Command, args []string) error {
	store, err := getTunnelStore()
	if err != nil {
		return err
	}
	defer store.Close()

	ctx := context.Background()
	before := time.Now().Add(-time.Duration(tunnelCleanDays) * 24 * time.Hour)

	count, err := store.PurgeDeletedBefore(ctx, before)
	if err != nil {
		return fmt.Errorf("clean tunnels: %w", err)
	}

	fmt.Printf("✓ Purged %d deleted tunnel definitions (deleted > %d days ago)\n", count, tunnelCleanDays)
	return nil
}

func resolveTunnelOwnerForQuery(
	ctx context.Context,
	store *channel.TunnelDefinitionStore,
	edgeID string,
	tunnelID string,
	ownerHint string,
) (string, error) {
	ownerHint = strings.TrimSpace(ownerHint)
	if ownerHint != "" {
		return ownerHint, nil
	}

	records, err := store.ListByEdge(ctx, edgeID, true)
	if err != nil {
		return "", fmt.Errorf("list tunnels for owner resolution: %w", err)
	}

	ownerSet := make(map[string]struct{})
	for _, rec := range records {
		if rec == nil || strings.TrimSpace(rec.TunnelID) != tunnelID {
			continue
		}
		owner := strings.TrimSpace(rec.OwnerUserID)
		if owner == "" {
			continue
		}
		ownerSet[owner] = struct{}{}
	}

	if len(ownerSet) == 0 {
		return "", fmt.Errorf("tunnel not found: %s", tunnelID)
	}
	if len(ownerSet) == 1 {
		for owner := range ownerSet {
			return owner, nil
		}
	}

	owners := make([]string, 0, len(ownerSet))
	for owner := range ownerSet {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	return "", fmt.Errorf(
		"tunnel %s has multiple owners on edge %s: %s (use --owner)",
		tunnelID,
		edgeID,
		strings.Join(owners, ", "),
	)
}

// prettyJSON indents a JSON string for human-readable display.
func prettyJSON(raw string) string {
	var v interface{}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	out, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		return raw
	}
	return "  " + string(out)
}
