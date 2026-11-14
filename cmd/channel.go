package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel"
	"icool.io/yat/edge/pkg/config"
)

var channelCmd = &cobra.Command{
	Use:   "channel",
	Short: "Manage channels",
	Long:  `Manage channels: list active channels, view channel details`,
}

var channelListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active channels",
	Long:  `List active channels (use --all to show all)`,
	RunE:  runChannelList,
}

var channelInfoCmd = &cobra.Command{
	Use:   "info <channel-id>",
	Short: "Show channel details",
	Long:  `Display detailed information about a specific channel`,
	Args:  cobra.ExactArgs(1),
	RunE:  runChannelInfo,
}

var (
	channelDBPath  string // 自定义数据库路径
	channelListAll bool   // 是否显示所有 channel（含非活跃）
)

// activeThreshold 定义活跃判定窗口：最近 15 分钟内有过活动视为活跃
const activeThreshold = 15 * time.Minute

func channelTypeName(typ fbMsg.ChannelType) string {
	switch typ {
	case fbMsg.ChannelTypeHTTP:
		return "HTTP"
	case fbMsg.ChannelTypeHTTPS:
		return "HTTPS"
	case fbMsg.ChannelTypeTCP:
		return "TCP"
	case fbMsg.ChannelTypeUDP:
		return "UDP"
	case fbMsg.ChannelTypeWIREGUARD:
		return "WIREGUARD"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", typ)
	}
}

func init() {
	rootCmd.AddCommand(channelCmd)
	channelCmd.AddCommand(channelListCmd)
	channelCmd.AddCommand(channelInfoCmd)

	// 全局标志：指定数据库路径
	channelCmd.PersistentFlags().StringVar(
		&channelDBPath,
		"db",
		"",
		fmt.Sprintf("Channel database path (default: %s/channels.db)", config.DefaultDataDir()),
	)
	channelListCmd.Flags().BoolVar(&channelListAll, "all", false, "Show all channels including inactive")
}

func getChannelStore() (*channel.ChannelStore, error) {
	var dbPath string
	defaultDBPath := filepath.Join(config.DefaultDataDir(), "channels.db")

	if channelDBPath != "" {
		// 使用用户指定的路径
		dbPath = channelDBPath
	} else if dataDir != "" {
		dbPath = filepath.Join(dataDir, "channels.db")
	} else {
		// 尝试多个默认路径
		candidates := []string{
			defaultDBPath,
			filepath.Join(os.Getenv("HOME"), ".yat/edge/channels.db"), // 用户目录
			"/var/lib/yat/edge/channels.db",                           // Linux 系统路径
		}

		// 选择第一个存在的数据库文件
		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				dbPath = candidate
				break
			}
		}

		// 如果都不存在，使用默认路径
		if dbPath == "" {
			dbPath = defaultDBPath
		}
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	return channel.NewChannelStore(dbPath)
}

// loadAssignedDomainForCLI loads the assigned domain from local storage for CLI display.
func loadAssignedDomainForCLI() string {
	dir := config.DefaultDataDir()
	if dataDir != "" {
		dir = dataDir
	}
	d, _ := config.LoadAssignedDomain(dir)
	return d
}

// composeDomainForDisplay composes subdomain.assignedDomain for CLI display.
func composeDomainForDisplay(subdomain, assignedDomain string) string {
	if subdomain == "" {
		return "-"
	}
	if assignedDomain == "" {
		return subdomain
	}
	return subdomain + "." + assignedDomain
}

type runtimeStatusSnapshot struct {
	loaded          bool
	connRemoteAddrs map[string]string
	channelStates   map[string]string
}

// loadRuntimeStatusSnapshot 从 runtime 的 status.json 中读取当前 channel 的运行时状态。
// CLI 作为独立进程，无法直接访问运行中的 Session，改通过 StatusManager 落盘的 status.json 透传。
func loadRuntimeStatusSnapshot() runtimeStatusSnapshot {
	snapshot := runtimeStatusSnapshot{
		loaded:          false,
		connRemoteAddrs: map[string]string{},
		channelStates:   map[string]string{},
	}

	dir := config.DefaultDataDir()
	if dataDir != "" {
		dir = dataDir
	}
	statusPath := filepath.Join(dir, "status.json")
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return snapshot
	}
	var raw struct {
		Targets []struct {
			ID             string `json:"id"`
			ConnRemoteAddr string `json:"conn_remote_addr"`
			State          string `json:"state"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return snapshot
	}
	result := runtimeStatusSnapshot{
		loaded:          true,
		connRemoteAddrs: make(map[string]string, len(raw.Targets)),
		channelStates:   make(map[string]string, len(raw.Targets)),
	}
	for _, t := range raw.Targets {
		if t.ID == "" {
			continue
		}
		if t.ConnRemoteAddr != "" {
			result.connRemoteAddrs[t.ID] = t.ConnRemoteAddr
		}
		if state := normalizeChannelStateForDisplay(t.State); state != "" {
			result.channelStates[t.ID] = state
		}
	}
	return result
}

func normalizeChannelStateForDisplay(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return ""
	}
	return value
}

func runChannelList(cmd *cobra.Command, args []string) error {
	store, err := getChannelStore()
	if err != nil {
		return err
	}
	defer store.Close()

	ctx := context.Background()
	channels, err := store.List(ctx)
	if err != nil {
		return fmt.Errorf("list channels: %w", err)
	}

	if len(channels) == 0 {
		fmt.Println("No channels found")
		return nil
	}

	assignedDomain := loadAssignedDomainForCLI()
	runtimeStatus := loadRuntimeStatusSnapshot()
	connRemoteAddrs := runtimeStatus.connRemoteAddrs
	channelStates := runtimeStatus.channelStates
	activeAfter := time.Now().Add(-activeThreshold)

	// 如果不是 --all 模式，过滤非活跃 channel
	if !channelListAll {
		filtered := channels[:0]
		for _, ch := range channels {
			if ch.LastActiveAt.After(activeAfter) {
				filtered = append(filtered, ch)
			}
		}
		channels = filtered
	}

	if len(channels) == 0 {
		if channelListAll {
			fmt.Println("No channels found")
		} else {
			fmt.Println("No active channels found (use --all to show all)")
		}
		return nil
	}

	// 使用 tabwriter 格式化输出
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CHANNEL ID\tTYPE\tSTATE\tDOMAIN\tCUSTOM DOMAIN\tCLIENT CONN\tLOCAL ADDR\tLAST ACTIVE")
	fmt.Fprintln(w, "----------\t----\t-----\t------\t-------------\t-----------\t----------\t-----------")

	for _, ch := range channels {
		typeName := channelTypeName(ch.Type)
		state := channelStates[ch.ChannelID]
		if state == "" {
			if runtimeStatus.loaded {
				state = "inactive"
			} else {
				state = "unknown"
			}
		}

		domain := composeDomainForDisplay(ch.Subdomain, assignedDomain)
		customDomain := ch.AliasDomain
		if customDomain == "" {
			customDomain = "-"
		}

		connRemoteAddr := connRemoteAddrs[ch.ChannelID]
		if connRemoteAddr == "" {
			connRemoteAddr = "-"
		}

		lastActive := ch.LastActiveAt.Format("2006-01-02 15:04:05")

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			ch.ChannelID,
			typeName,
			state,
			domain,
			customDomain,
			connRemoteAddr,
			ch.LocalAddr,
			lastActive,
		)
	}

	return w.Flush()
}

func runChannelInfo(cmd *cobra.Command, args []string) error {
	channelID := args[0]

	store, err := getChannelStore()
	if err != nil {
		return err
	}
	defer store.Close()

	ctx := context.Background()
	ch, err := store.Get(ctx, channelID)
	if err != nil {
		return fmt.Errorf("get channel: %w", err)
	}

	if ch == nil {
		return fmt.Errorf("channel not found: %s", channelID)
	}

	// 显示详细信息
	fmt.Printf("Channel Information:\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Channel ID:       %s\n", ch.ChannelID)
	fmt.Printf("Session ID:       %s\n", ch.SessionID)

	typeName := channelTypeName(ch.Type)
	runtimeStatus := loadRuntimeStatusSnapshot()
	connRemoteAddr := runtimeStatus.connRemoteAddrs[ch.ChannelID]
	state := runtimeStatus.channelStates[ch.ChannelID]
	if state == "" {
		if runtimeStatus.loaded {
			state = "inactive"
		} else {
			state = "unknown"
		}
	}
	if connRemoteAddr == "" {
		connRemoteAddr = "-"
	}
	fmt.Printf("Type:             %s\n", typeName)
	fmt.Printf("State:            %s\n", state)
	fmt.Printf("Client Conn:      %s\n", connRemoteAddr)
	fmt.Printf("Local Address:    %s\n", ch.LocalAddr)
	fmt.Printf("Subdomain:        %s\n", ch.Subdomain)
	customDomain := ch.AliasDomain
	if customDomain == "" {
		customDomain = "-"
	}
	fmt.Printf("Custom Domain:    %s\n", customDomain)

	assignedDomain := loadAssignedDomainForCLI()
	composed := composeDomainForDisplay(ch.Subdomain, assignedDomain)
	fmt.Printf("Assigned Domain:  %s\n", composed)
	if ch.AliasDomain != "" && composed != "-" {
		fmt.Printf("DNS CNAME:        %s -> %s\n", ch.AliasDomain, composed)
	}

	fmt.Printf("Created At:       %s\n", ch.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Last Active:      %s\n", ch.LastActiveAt.Format("2006-01-02 15:04:05"))

	// 计算活跃时长
	duration := time.Since(ch.LastActiveAt)
	if duration < time.Minute {
		fmt.Printf("Inactive For:     %d seconds\n", int(duration.Seconds()))
	} else if duration < time.Hour {
		fmt.Printf("Inactive For:     %d minutes\n", int(duration.Minutes()))
	} else if duration < 24*time.Hour {
		fmt.Printf("Inactive For:     %d hours\n", int(duration.Hours()))
	} else {
		fmt.Printf("Inactive For:     %d days\n", int(duration.Hours()/24))
	}

	return nil
}
