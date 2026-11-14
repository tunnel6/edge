/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"icool.io/yat/edge/internal/daemon"
	"icool.io/yat/edge/internal/ipc"
	"icool.io/yat/edge/internal/server"
	"icool.io/yat/edge/pkg/config"
	"icool.io/yat/edge/pkg/i18n"
	logger "icool.io/yat/edge/pkg/log"
)

const (
	// StopRetryCount Number of retries when stopping
	StopRetryCount = 30
	// StopRetryInterval Interval between each retry
	StopRetryInterval = 100 * time.Millisecond
	// defaultServerStartLogFile is the fallback file used by `edge server start`.
	defaultServerStartLogFile = "/var/log/edge.log"
)

var (
	// Command line arguments (higher priority than config file)
	configFile  string
	daemonMode  bool
	pidFile     string
	sockFile    string
	listen      string
	publicAddr  string
	maxSessions int
	tlsCA       string
	tlsCert     string
	tlsKey      string

	customDomain             string
	channelBaseDomain        string
	channelCertificateSource string
	aliasDomainPolicy        string
	channelHTTPPort          uint16
	channelHTTPSPort         uint16
	tcpPortMin               uint16
	tcpPortMax               uint16
	udpPortMin               uint16
	udpPortMax               uint16
	maxTunnelsPerSession     int
	maxTunnelsTotal          int
	httpProxyAddr            string
	httpProxyTimeout         time.Duration
	channelHTTPBuffer        string
	channelHTTPBufferLock    bool
	httpProxyEnabled         bool
	tcpProxyEnabled          bool
	udpProxyEnabled          bool
	wireGuardEnabled         bool
	wireGuardRelayEnabled    bool
	wireGuardPublicEndpoint  string
	eagerStartHTTPProxy      bool
	autoEnableCapabilities   bool
	p2pEnabled               bool
	p2pUDPAddr               string
	pprofAddr                string

	startupConfigB64  string
	startupConfigJSON string
	logOutput         string
	logFile           string
	DefaultConfigFile = filepath.Join(os.Getenv("HOME"), ".yat/config.yml")
)

func normalizeNonNegativeInt(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

type logOutputFlagValue struct {
	value *string
}

func newLogOutputFlagValue(target *string) *logOutputFlagValue {
	return &logOutputFlagValue{value: target}
}

func (v *logOutputFlagValue) Set(raw string) error {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch normalized {
	case logger.OutputConsole, logger.OutputFile:
		*v.value = normalized
		return nil
	default:
		return fmt.Errorf("invalid log output %q, allowed values: %s, %s", raw, logger.OutputConsole, logger.OutputFile)
	}
}

func (v *logOutputFlagValue) String() string {
	if v == nil || v.value == nil {
		return ""
	}
	return *v.value
}

func (v *logOutputFlagValue) Type() string {
	return "log_output"
}

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "edge server",
	Long:  ``,
}
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "start the edge server",
	Long:  `Start the edge tunnel server in foreground or daemon mode`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := startServer(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}
var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stop the edge server",
	Long:  `Stop the running edge server daemon`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := stopServer(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Server stopped successfully")
	},
}
var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "restart the edge server",
	Long:  `Restart the edge server daemon`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := stopServer(); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
		time.Sleep(1 * time.Second)
		if err := startServer(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "show server status",
	Long:  `Show the running status of edge server`,
	Run: func(cmd *cobra.Command, args []string) {
		showStatus()
	},
}
var onlineCmd = &cobra.Command{
	Use:   "online",
	Short: "resume local channel services",
	Long:  `Resume channel services on the running Edge`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := markOnline(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Server marked as online successfully")
	},
}
var offlineCmd = &cobra.Command{
	Use:   "offline",
	Short: "suspend local channel services",
	Long:  `Suspend channel services on the running Edge`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := markOffline(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Server marked as offline successfully")
	},
}

func init() {
	// Add command line arguments

	startCmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path (default: ~/.yat/config.yml, fallback: ~/.yat/config.yaml)")
	startCmd.Flags().BoolVarP(&daemonMode, "daemon", "d", false, "run in daemon mode")
	startCmd.Flags().StringVar(&pidFile, "pid-file", daemon.DefaultPidFile, "pid file path")
	startCmd.Flags().StringVar(&sockFile, "sock-file", daemon.DefaultSockFile, "sock file path")
	addTunnelCoreFlags(startCmd)
	addTunnelOptionFlags(startCmd)

	stopCmd.Flags().StringVar(&pidFile, "pid-file", daemon.DefaultPidFile, "pid file path")
	stopCmd.Flags().StringVar(&sockFile, "sock-file", daemon.DefaultSockFile, "sock file path")
	statusCmd.Flags().StringVar(&pidFile, "pid-file", daemon.DefaultPidFile, "pid file path")
	statusCmd.Flags().StringVar(&sockFile, "sock-file", daemon.DefaultSockFile, "sock file path")
	restartCmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	restartCmd.Flags().StringVar(&pidFile, "pid-file", daemon.DefaultPidFile, "pid file path")
	restartCmd.Flags().StringVar(&sockFile, "sock-file", daemon.DefaultSockFile, "sock file path")
	addTunnelOptionFlags(restartCmd)
	addTunnelCoreFlags(restartCmd)
	onlineCmd.Flags().StringVar(&pidFile, "pid-file", daemon.DefaultPidFile, "pid file path")
	onlineCmd.Flags().StringVar(&sockFile, "sock-file", daemon.DefaultSockFile, "sock file path")
	offlineCmd.Flags().StringVar(&pidFile, "pid-file", daemon.DefaultPidFile, "pid file path")
	offlineCmd.Flags().StringVar(&sockFile, "sock-file", daemon.DefaultSockFile, "sock file path")

	serverCmd.AddCommand(startCmd, stopCmd, restartCmd, statusCmd, onlineCmd, offlineCmd)
	rootCmd.AddCommand(serverCmd)
}

func addTunnelCoreFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&publicAddr, "public", "", "public IP or domain (without port)")
	cmd.Flags().StringVar(&customDomain, "domain", "", "custom domain for HTTP channels (deployment override)")
	cmd.Flags().StringVar(&channelBaseDomain, "channel.base_domain", "", "required base domain for HTTP channels")
	cmd.Flags().StringVar(&channelCertificateSource, "channel.https.certificate_source", "", "HTTPS certificate source: dns01 or upload")
	cmd.Flags().StringVar(&aliasDomainPolicy, "channel.alias_domain_policy", "", "alias domain policy: disabled|optional|required (deployment override)")
	cmd.Flags().StringVar(&listen, "tunnel.listen", "", "tunnel listen address (deployment override)")
	cmd.Flags().IntVar(&maxSessions, "tunnel.max_sessions", 0, "max sessions (deployment override)")
	cmd.Flags().StringVar(&tlsCA, "tunnel.tls.ca", "", "TLS CA certificate path (deployment override)")
	cmd.Flags().StringVar(&tlsCert, "tunnel.tls.cert", "", "TLS server certificate path (deployment override)")
	cmd.Flags().StringVar(&tlsKey, "tunnel.tls.key", "", "TLS server key path (deployment override)")
	cmd.Flags().StringVar(&startupConfigB64, "startup.config_b64", "", "startup config (base64 encoded JSON)")
	cmd.Flags().StringVar(&startupConfigJSON, "startup.config_json", "", "startup config (JSON)")
	cmd.Flags().Var(newLogOutputFlagValue(&logOutput), "log.output", "log output mode: console or file (deployment override)")
	cmd.Flags().StringVar(&logFile, "log.file", "", "log file path when log.output=file (deployment override)")
	cmd.Flags().StringVar(&logLevel, "log.level", "", "log level: debug, info, warn, error, fatal, panic (deployment override)")
}

func addTunnelOptionFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&httpProxyEnabled, "channel.http.enable", true, "enable HTTP channels/proxy (deployment override)")
	cmd.Flags().Uint16Var(&channelHTTPPort, "channel.http.port", 0, "HTTP proxy port for channels (deployment override)")
	cmd.Flags().Uint16Var(&channelHTTPSPort, "channel.https.port", 0, "HTTPS proxy port for channels (deployment override)")
	cmd.Flags().StringVar(&httpProxyAddr, "channel.http.addr", "", "HTTP proxy listen addr (deployment override)")
	cmd.Flags().DurationVar(&httpProxyTimeout, "channel.http.timeout", 0, "HTTP proxy request timeout (deployment override)")
	cmd.Flags().StringVar(&channelHTTPBuffer, "channel.http.buffer", "", "HTTP channel read buffer size, supports K/M suffix (deployment override)")
	cmd.Flags().BoolVar(&channelHTTPBufferLock, "channel.http.buffer.lock", false, "lock HTTP channel buffer to fixed size and disable dynamic window (deployment override)")
	cmd.Flags().BoolVar(&eagerStartHTTPProxy, "channel.http.eager_start", false, "start HTTP proxy on boot (deployment override)")

	cmd.Flags().BoolVar(&tcpProxyEnabled, "channel.tcp.enable", true, "enable TCP channels/proxy (deployment override)")
	cmd.Flags().Uint16Var(&tcpPortMin, "channel.tcp.port_min", 0, "TCP port min (deployment override)")
	cmd.Flags().Uint16Var(&tcpPortMax, "channel.tcp.port_max", 0, "TCP port max (deployment override)")

	cmd.Flags().BoolVar(&udpProxyEnabled, "channel.udp.enable", true, "enable UDP channels/proxy (deployment override)")
	cmd.Flags().Uint16Var(&udpPortMin, "channel.udp.port_min", 0, "UDP port min (deployment override)")
	cmd.Flags().Uint16Var(&udpPortMax, "channel.udp.port_max", 0, "UDP port max (deployment override)")

	cmd.Flags().IntVar(&maxTunnelsPerSession, "tunnel.limits.max_per_session", 0, "max tunnel definitions per user session, 0 means unlimited (deployment override)")
	cmd.Flags().IntVar(&maxTunnelsTotal, "tunnel.limits.max_total", 0, "max tunnel definitions for this edge, 0 means unlimited (deployment override)")

	cmd.Flags().BoolVar(&wireGuardEnabled, "channel.wireguard.enable", true, "enable wireguard handlers (deployment override)")
	cmd.Flags().BoolVar(&wireGuardRelayEnabled, "channel.wireguard.relay_enabled", false, "enable edge-hosted WireGuard relay runtime for relay-capable networks (deployment override)")
	cmd.Flags().StringVar(&wireGuardPublicEndpoint, "channel.wireguard.public_endpoint", "", "WireGuard relay public IP or domain without port; defaults to --public / node.public_address (deployment override)")
	cmd.Flags().BoolVar(&autoEnableCapabilities, "server.capabilities.auto_enable", true, "auto enable services from client capabilities (deployment override)")
	cmd.Flags().BoolVar(&p2pEnabled, "server.capabilities.p2p", true, "enable P2P capability on edge (deployment override)")
	cmd.Flags().StringVar(&p2pUDPAddr, "channel.p2p.udp_addr", "", "P2P UDP listen addr, e.g. 0.0.0.0:9000 (deployment override)")
	cmd.Flags().StringVar(&pprofAddr, "pprof-addr", "", "pprof HTTP listen addr, e.g. 127.0.0.1:6060 (empty = disabled)")
}

func defaultServerLogFilePath() string {
	return defaultServerStartLogFile
}

func configureLoggerForServerStartDefault() error {
	return logger.ConfigureOutput(logger.OutputFile, defaultServerLogFilePath())
}

func configureLoggerFromConfig(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}
	output := strings.TrimSpace(cfg.Log.Output)
	file := strings.TrimSpace(cfg.Log.File)
	if output == "" {
		// server start defaults to file output unless config explicitly overrides.
		output = logger.OutputFile
	}
	if output == logger.OutputFile && file == "" {
		file = defaultServerLogFilePath()
	}
	if cfg.Log.Level != "" {
		if level, err := logrus.ParseLevel(cfg.Log.Level); err == nil {
			logger.SetLogLevel(level)
		}
	}
	return logger.ConfigureOutput(output, file)
}

// startServer Start server
func startServer(cmd *cobra.Command) error {
	// if err := configureLoggerForServerStartDefault(); err != nil {
	// 	return fmt.Errorf("configure default logger for server start: %w", err)
	// }

	// 0. Display Banner (foreground mode only)
	if !daemonMode {
		PrintBanner()
	}

	// 1. Load configuration
	cfg, err := loadConfig(cmd)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := configureLoggerFromConfig(cfg); err != nil {
		return fmt.Errorf("configure logger from config: %w", err)
	}

	// 2. Handle daemon mode
	dmn := daemon.New(pidFile)
	if daemonMode {
		if err := dmn.Daemonize(); err != nil {
			return fmt.Errorf("daemonize: %w", err)
		}
		// If we return here, it means daemon process has started, parent process has exited
	}

	// 3. Write PID file
	if err := dmn.WritePid(); err != nil {
		return fmt.Errorf("write pid: %w", err)
	}
	defer dmn.RemovePid()

	// 4. Create edge server
	startupCfg, tunnelOptions, err := applyStartupConfigFromFlags(cmd, cfg)
	if err != nil {
		return err
	}
	if startupCfg == nil {
		// 没有 StartupConfig 时，仍然需要处理 --public 等命令行参数
		tunnelOptions = buildTunnelServerOptions(cmd)
	}
	// 确保公网地址已设置（无论是否使用 startup config）
	if err := cfg.ValidateChannelDomain(); err != nil {
		return err
	}
	if err := ensurePublicAddress(cfg); err != nil {
		return err
	}
	server, err := NewEdgeServer(cfg, pidFile, sockFile, tunnelOptions...)
	if err != nil {
		return fmt.Errorf("create edge server: %w", err)
	}

	// 5. Start server
	logger.Infof("starting edge server, mode: %s", getMode())
	if err := server.Start(); err != nil {
		return fmt.Errorf("start edge server: %w", err)
	}
	defer server.Stop()

	// 6. Load AssignedDomain and verify DNS (after bootstrap, AssignedDomain may be assigned)
	if cfg.Channel.GetAssignedDomain() == "" {
		if bd, err := config.LoadAssignedDomain(cfg.GetDataDir()); err == nil && bd != "" {
			changed, persistErr := cfg.Channel.SetAssignedDomainWithError(bd)
			if persistErr != nil {
				logger.Warnf("persist assigned domain from local failed: data_dir=%s assigned_domain=%s err=%v", cfg.GetDataDir(), bd, persistErr)
			}
			logger.Infof("loaded assigned domain from local: %s (changed=%t, data_dir=%s)", bd, changed, cfg.GetDataDir())
		}
	}

	// 7. Verify CustomDomain DNS resolution (only for user-specified domains, not system-assigned AssignedDomain)
	if cfg.Channel.GetCustomDomain() != "" {
		if err := resolveCustomDomain(cfg); err != nil {
			return err
		}
	}

	// 8. Check and cache DNS/cert status for both domains (one-time at startup)
	cfg.Channel.DomainConfig.CheckAndStoreDNSStatus(buildCertChecker(cfg))
	logDomainStatus(cfg)

	if !daemonMode {
		logger.Infof("edge server started successfully, pid: %d", os.Getpid())
		fmt.Println("Edge server is running. Press Ctrl+C to stop.")
		printStartupSummary(cfg, server)
	}

	// Start pprof HTTP server if enabled
	if pprofAddr != "" {
		go func() {
			logger.Infof("pprof HTTP server listening on %s", pprofAddr)
			if err := http.ListenAndServe(pprofAddr, nil); err != nil {
				logger.Warnf("pprof server error: %v", err)
			}
		}()
	}

	// 9. Block and wait
	select {}
}

// printStartupSummary Print startup parameter summary (ANSI table)
func printStartupSummary(cfg *config.Config, edgeServer *EdgeServer) {
	// ANSI color codes
	const (
		Reset   = "\033[0m"
		Bold    = "\033[1m"
		Green   = "\033[32m"
		Cyan    = "\033[36m"
		Yellow  = "\033[33m"
		Blue    = "\033[34m"
		Magenta = "\033[35m"
	)

	// Helper function: print separator line
	printLine := func() {
		fmt.Println(Blue + strings.Repeat("─", 60) + Reset)
	}

	// Helper function: print key-value pair
	printItem := func(key, value string) {
		if value == "" {
			value = "-"
		}
		fmt.Printf("%s%-25s%s %s%s%s\n", Cyan, key, Reset, Green, value, Reset)
	}

	fmt.Println()
	printLine()
	fmt.Printf("%s%s             🚀 Edge Server Configuration             %s\n", Bold, Yellow, Reset)
	printLine()

	// Core configuration
	printItem("Build", config.Build)
	printItem("Version", config.Version)
	printItem("Node ID", cfg.Node.ID)
	printItem("Public Address", cfg.Node.PublicAddress)
	printItem("Listen Address", cfg.Tunnel.Listen)
	printItem("Max Sessions", fmt.Sprintf("%d", cfg.Tunnel.MaxSessions))
	fmt.Printf("%s%-25s%s %s● ONLINE%s\n", Cyan, "Status", Reset, Green, Reset)

	printLine()
	// Channel configuration
	printItem("HTTP Proxy", fmt.Sprintf("Enabled: %v, Port: %d", cfg.Proxy.HTTP.Enabled, cfg.Proxy.HTTP.Port))
	printItem("HTTPS Proxy Port", fmt.Sprintf("%d", cfg.Proxy.HTTP.HTTPSPort))
	if assignedDomain := cfg.Channel.GetAssignedDomain(); assignedDomain != "" {
		printItem("Assigned Domain", assignedDomain)
	}
	if customDomain := cfg.Channel.GetCustomDomain(); customDomain != "" {
		printItem("Custom Domain", customDomain)
	}
	printItem("TCP Ports", fmt.Sprintf("%d - %d", cfg.Proxy.TCP.PortMin, cfg.Proxy.TCP.PortMax))
	printItem("UDP Ports", fmt.Sprintf("%d - %d", cfg.Proxy.UDP.PortMin, cfg.Proxy.UDP.PortMax))
	printItem("P2P_ICE", fmt.Sprintf("Enabled: %v", cfg.Proxy.ICE.Enabled))
	printItem("WireGuard", fmt.Sprintf("Enabled: %v", cfg.Proxy.WireGuard.Enabled))

	// OSS Pairing info
	if edgeServer != nil && edgeServer.GetPairToken() != "" {
		printLine()
		fmt.Printf("%s%s             📱 FE Pairing (mTLS Tunnel)                  %s\n", Bold, Magenta, Reset)
		printLine()
		pairToken := edgeServer.GetPairToken()
		// Display tunnel address for pairing (FE connects via mTLS, not HTTPS)
		tunnelAddr := cfg.Tunnel.Listen
		tunnelHost := cfg.Node.PublicAddress
		if tunnelHost == "" {
			tunnelHost = "<your-edge-ip>"
		}
		if _, port, err := net.SplitHostPort(tunnelAddr); err == nil {
			tunnelAddr = net.JoinHostPort(tunnelHost, port)
		} else {
			tunnelAddr = net.JoinHostPort(tunnelHost, "443")
		}
		printItem("Tunnel Address", tunnelAddr)
		printItem("Pairing Token", pairToken)
		fmt.Printf("%s\n", Yellow+"  Open FE → Add Edge → Enter tunnel address and token to pair"+Reset)
		fmt.Printf("%s\n", Cyan+"  Token valid for 1 hour, one-time use only"+Reset)
		fmt.Printf("%s\n", Cyan+"  Regenerate: edge pair generate"+Reset)
	}

	printLine()
	fmt.Println()
}

// stopServer Stop server
func stopServer() error {
	dmn := daemon.New(pidFile)

	running, pid, err := dmn.Status()
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	if !running {
		return fmt.Errorf("server is not running")
	}

	fmt.Printf("Stopping server (PID: %d)...\n", pid)
	if err := dmn.Stop(); err != nil {
		return fmt.Errorf("stop server: %w", err)
	}

	// Wait for process to stop
	for i := 0; i < StopRetryCount; i++ {
		if !dmn.IsRunning() {
			return nil
		}
		time.Sleep(StopRetryInterval)
	}

	return fmt.Errorf("server did not stop in time")
}

// showStatus Show status
func showStatus() {
	dmn := daemon.New(pidFile)
	runtimeDataDir := strings.TrimSpace(dataDir)
	if runtimeDataDir == "" {
		runtimeDataDir = config.DefaultDataDir()
	}
	statusPath := filepath.Join(runtimeDataDir, "status.json")

	running, pid, err := dmn.Status()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Data dir: %s\n", runtimeDataDir)
	fmt.Printf("Status file: %s\n", statusPath)
	if running {
		fmt.Printf("Edge server is running\n")
		fmt.Printf("PID: %d\n", pid)
		fmt.Printf("PID file: %s\n", dmn.GetPidFile())
	} else {
		fmt.Println("Edge server is not running")
	}

	status, err := loadEdgeStatus(statusPath)
	if err != nil {
		fmt.Printf("Runtime status: unavailable (%v)\n", err)
		return
	}

	// Online/Offline status with color
	if status.Online {
		fmt.Printf("Status: \033[32m● ONLINE\033[0m\n")
	} else {
		fmt.Printf("Status: \033[31m● OFFLINE\033[0m\n")
	}

	display := func(v string) string {
		if strings.TrimSpace(v) == "" {
			return "-"
		}
		return v
	}

	fmt.Println("WireGuard runtime:")
	fmt.Printf("  enabled: %t\n", status.WireGuardEnabled)
	fmt.Printf("  relay_enabled: %t\n", status.WireGuardRelayEnabled)
	fmt.Printf("  relay_runtime_ready: %t\n", status.WireGuardRelayRuntimeReady)
	fmt.Printf("  interface_prefix: %s\n", display(status.WireGuardInterfacePrefix))
	fmt.Printf("  listen_port_base: %d\n", status.WireGuardListenPortBase)
	fmt.Printf("  key_dir: %s\n", display(status.WireGuardKeyDir))
	fmt.Printf("  public_endpoint: %s\n", display(status.WireGuardPublicEndpoint))
	fmt.Printf("  relay_runtime_state: %s\n", func() string {
		if status.WireGuardRelayRuntimeReady {
			return "ready"
		}
		return "not-ready"
	}())
	fmt.Println("Port usage:")
	fmt.Printf("  tcp: %d/%d (%s)\n", status.PortUsage.TCPUsed, status.PortUsage.TCPTotal, display(status.PortUsage.TCPRange))
	fmt.Printf("  udp: %d/%d (%s)\n", status.PortUsage.UDPUsed, status.PortUsage.UDPTotal, display(status.PortUsage.UDPRange))
	fmt.Printf("  http: %d\n", status.PortUsage.HTTPPort)
	fmt.Printf("  https: %d\n", status.PortUsage.HTTPSPort)
}

func buildTunnelServerOptions(cmd *cobra.Command) []server.ServerOption {
	opts := make([]server.ServerOption, 0, 16)

	if cmd.Flags().Changed("channel.http.enable") {
		opts = append(opts, server.WithHTTPProxyEnabled(httpProxyEnabled))
	}
	if cmd.Flags().Changed("channel.tcp.enable") {
		opts = append(opts, server.WithTCPProxyEnabled(tcpProxyEnabled))
	}
	if cmd.Flags().Changed("channel.udp.enable") {
		opts = append(opts, server.WithUDPProxyEnabled(udpProxyEnabled))
	}
	if cmd.Flags().Changed("channel.wireguard.enable") {
		opts = append(opts, server.WithWireGuardEnabled(wireGuardEnabled))
	}
	if cmd.Flags().Changed("channel.http.eager_start") {
		opts = append(opts, server.WithEagerStartHTTPProxy(eagerStartHTTPProxy))
	}
	if cmd.Flags().Changed("server.capabilities.auto_enable") {
		opts = append(opts, server.WithAutoEnableFromCapabilities(autoEnableCapabilities))
	}
	if cmd.Flags().Changed("server.capabilities.p2p") {
		opts = append(opts, server.WithP2PEnabled(p2pEnabled))
	}
	if cmd.Flags().Changed("channel.http.port") && channelHTTPPort != 0 {
		opts = append(opts, server.WithRegistryHTTPPort(channelHTTPPort))
	}
	if cmd.Flags().Changed("channel.https.port") {
		opts = append(opts, server.WithRegistryHTTPSPort(channelHTTPSPort))
	}
	if cmd.Flags().Changed("channel.tcp.port_min") || cmd.Flags().Changed("channel.tcp.port_max") {
		if tcpPortMin != 0 || tcpPortMax != 0 {
			opts = append(opts, server.WithTCPPortRange(tcpPortMin, tcpPortMax))
		}
	}
	if cmd.Flags().Changed("channel.udp.port_min") || cmd.Flags().Changed("channel.udp.port_max") {
		if udpPortMin != 0 || udpPortMax != 0 {
			opts = append(opts, server.WithUDPPortRange(udpPortMin, udpPortMax))
		}
	}
	if cmd.Flags().Changed("channel.http.addr") && httpProxyAddr != "" {
		opts = append(opts, server.WithHTTPProxyAddr(httpProxyAddr))
	}
	if cmd.Flags().Changed("channel.http.timeout") && httpProxyTimeout != 0 {
		opts = append(opts, server.WithHTTPProxyTimeout(httpProxyTimeout))
	}
	if cmd.Flags().Changed("channel.http.buffer") && channelHTTPBuffer != "" {
		size, err := config.ParseByteSize(channelHTTPBuffer)
		if err != nil {
			logger.Warnf("ignore invalid channel.http.buffer=%q: %v", channelHTTPBuffer, err)
		} else {
			opts = append(opts, server.WithHTTPBufferSize(size))
		}
	}
	if cmd.Flags().Changed("channel.http.buffer.lock") {
		opts = append(opts, server.WithHTTPBufferLock(channelHTTPBufferLock))
	}

	if cmd.Flags().Changed("channel.p2p.udp_addr") && strings.TrimSpace(p2pUDPAddr) != "" {
		opts = append(opts, server.WithP2PUDPAddr(strings.TrimSpace(p2pUDPAddr)))
	}
	return opts
}

func expandHomePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	if trimmed == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return home
		}
		return trimmed
	}
	if strings.HasPrefix(trimmed, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, strings.TrimPrefix(trimmed, "~/"))
		}
	}
	return trimmed
}

func resolveConfigFilePath(raw string) string {
	path := expandHomePath(raw)
	if path == "" {
		return path
	}
	if _, err := os.Stat(path); err == nil {
		return path
	}

	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".yml":
		candidate := strings.TrimSuffix(path, ext) + ".yaml"
		if _, err := os.Stat(candidate); err == nil {
			logger.Infof("config fallback: %s -> %s", path, candidate)
			return candidate
		}
	case ".yaml":
		candidate := strings.TrimSuffix(path, ext) + ".yml"
		if _, err := os.Stat(candidate); err == nil {
			logger.Infof("config fallback: %s -> %s", path, candidate)
			return candidate
		}
	}

	return path
}

// loadConfig Load configuration (command line args take precedence)
func loadConfig(cmd *cobra.Command) (cfg *config.Config, err error) {

	// Default config file path
	if configFile == "" {
		configFile = DefaultConfigFile
	}
	configFile = resolveConfigFilePath(configFile)

	// Load config file, use default config if not exists
	if _, statErr := os.Stat(configFile); statErr == nil {
		cfg, err = config.LoadConfig(configFile)
		if err != nil {
			return nil, fmt.Errorf("load config file: %w", err)
		}
		logger.Infof("loaded config from file: %s", configFile)
	} else {
		// Config file not found, use default config
		logger.Warnf("config file not found, using defaults, path: %s", configFile)
		cfg = config.DefaultConfig()
	}

	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	if strings.TrimSpace(dataDir) != "" {
		cfg.DataDir = strings.TrimSpace(dataDir)
	}

	// Normalize config (fill in data dir and TLS paths)
	cfg.Channel.DomainConfig = *config.NewDomainConfig(cfg.GetDataDir())
	_ = cfg.Channel.LoadFromLocal()
	if cfg.Channel.CustomDomain != "" {
		cfg.Channel.SetCustomDomain(cfg.Channel.CustomDomain)
	}
	config.NormalizeConfig(cfg)
	// Command line args override config file
	if cmd.Flags().Changed("tunnel.listen") && listen != "" {
		cfg.Tunnel.Listen = listen
	}
	if cmd.Flags().Changed("tunnel.max_sessions") && maxSessions > 0 {
		cfg.Tunnel.MaxSessions = maxSessions
	}
	if cmd.Flags().Changed("tunnel.tls.ca") && tlsCA != "" {
		cfg.Tunnel.TLS.CA = tlsCA
	}
	if cmd.Flags().Changed("tunnel.tls.cert") && tlsCert != "" {
		cfg.Tunnel.TLS.Cert = tlsCert
	}
	if cmd.Flags().Changed("tunnel.tls.key") && tlsKey != "" {
		cfg.Tunnel.TLS.Key = tlsKey
	}

	if cmd.Flags().Changed("log.output") {
		cfg.Log.Output = strings.TrimSpace(logOutput)
	}
	if cmd.Flags().Changed("log.file") && strings.TrimSpace(logFile) != "" {
		cfg.Log.File = strings.TrimSpace(logFile)
	}

	if cmd.Flags().Changed("domain") && customDomain != "" {
		cfg.Channel.SetCustomDomain(customDomain)
	}
	if cmd.Flags().Changed("channel.base_domain") {
		cfg.Channel.BaseDomain = channelBaseDomain
	}
	if cmd.Flags().Changed("channel.https.certificate_source") {
		cfg.Proxy.HTTP.CertificateSource = channelCertificateSource
	}
	if cmd.Flags().Changed("channel.http.port") && channelHTTPPort != 0 {
		cfg.Proxy.HTTP.Port = channelHTTPPort
	}
	if cmd.Flags().Changed("channel.https.port") {
		cfg.Proxy.HTTP.HTTPSPort = channelHTTPSPort
	}
	if cmd.Flags().Changed("channel.tcp.port_min") && tcpPortMin != 0 {
		cfg.Proxy.TCP.PortMin = tcpPortMin
	}
	if cmd.Flags().Changed("channel.tcp.port_max") && tcpPortMax != 0 {
		cfg.Proxy.TCP.PortMax = tcpPortMax
	}
	if cmd.Flags().Changed("channel.udp.port_min") && udpPortMin != 0 {
		cfg.Proxy.UDP.PortMin = udpPortMin
	}
	if cmd.Flags().Changed("channel.udp.port_max") && udpPortMax != 0 {
		cfg.Proxy.UDP.PortMax = udpPortMax
	}
	if cmd.Flags().Changed("tunnel.limits.max_per_session") {
		cfg.Tunnel.Limits.MaxPerSession = normalizeNonNegativeInt(maxTunnelsPerSession)
	}
	if cmd.Flags().Changed("tunnel.limits.max_total") {
		cfg.Tunnel.Limits.MaxTotal = normalizeNonNegativeInt(maxTunnelsTotal)
	}
	if cmd.Flags().Changed("channel.http.enable") {
		cfg.Proxy.HTTP.Enabled = httpProxyEnabled
	}
	if cmd.Flags().Changed("channel.tcp.enable") {
		cfg.Proxy.TCP.Enabled = tcpProxyEnabled
	}
	if cmd.Flags().Changed("channel.udp.enable") {
		cfg.Proxy.UDP.Enabled = udpProxyEnabled
	}
	if cmd.Flags().Changed("channel.http.addr") && httpProxyAddr != "" {
		cfg.Proxy.HTTP.Addr = httpProxyAddr
	}
	if cmd.Flags().Changed("channel.http.timeout") && httpProxyTimeout != 0 {
		cfg.Proxy.HTTP.Timeout = httpProxyTimeout
	}
	if cmd.Flags().Changed("channel.http.buffer") && channelHTTPBuffer != "" {
		if _, err := config.ParseByteSize(channelHTTPBuffer); err != nil {
			logger.Warnf("ignore invalid channel.http.buffer=%q: %v", channelHTTPBuffer, err)
		} else {
			cfg.Proxy.HTTP.Buffer = channelHTTPBuffer
		}
	}
	if cmd.Flags().Changed("channel.http.buffer.lock") {
		cfg.Proxy.HTTP.BufferLock = channelHTTPBufferLock
	}
	if cmd.Flags().Changed("channel.http.eager_start") {
		cfg.Proxy.HTTP.EagerStart = eagerStartHTTPProxy
	}
	if cmd.Flags().Changed("channel.wireguard.enable") {
		cfg.Proxy.WireGuard.Enabled = wireGuardEnabled
	}
	if cmd.Flags().Changed("channel.wireguard.relay_enabled") {
		cfg.Proxy.WireGuard.RelayEnabled = wireGuardRelayEnabled
	}
	if cmd.Flags().Changed("channel.wireguard.public_endpoint") {
		cfg.Proxy.WireGuard.PublicEndpoint = strings.TrimSpace(wireGuardPublicEndpoint)
	}
	if cmd.Flags().Changed("server.capabilities.p2p") {
		cfg.Proxy.ICE.Enabled = p2pEnabled
	}
	if cmd.Flags().Changed("channel.p2p.udp_addr") && strings.TrimSpace(p2pUDPAddr) != "" {
		cfg.Proxy.ICE.UDPAddr = strings.TrimSpace(p2pUDPAddr)
		cfg.Proxy.ICE.Enabled = true
	}
	return cfg, nil
}

// isStdinTerminal checks whether stdin is connected to a terminal (TTY).
// Returns false when running under systemd, piped input, or redirected stdin.
func isStdinTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// detectPublicIPSequential 依次尝试各端点检测公网 IP（每个 2s 超时）
// 返回首个成功的 IPv4（优先）或 IPv6 地址，全部失败返回空
func detectPublicIPSequential() string {
	type endpoint struct {
		url   string
		parse func([]byte) string
	}

	endpoints := []endpoint{
		{"https://ip-query.com/api/myip", func(b []byte) string {
			var ip struct {
				IP string `json:"ip"`
			}
			if err := json.Unmarshal(b, &ip); err != nil {
				return ""
			}
			return ip.IP
		}},
		{"https://api.ipify.org", func(b []byte) string { return strings.TrimSpace(string(b)) }},
		{"https://ipv4.icanhazip.com", func(b []byte) string { return strings.TrimSpace(string(b)) }},
		{"https://v4.ident.me", func(b []byte) string { return strings.TrimSpace(string(b)) }},
		{"https://api6.ipify.org", func(b []byte) string { return strings.TrimSpace(string(b)) }},
		{"https://ipv6.icanhazip.com", func(b []byte) string { return strings.TrimSpace(string(b)) }},
		{"https://v6.ident.me", func(b []byte) string { return strings.TrimSpace(string(b)) }},
	}

	timeout := 2 * time.Second
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
		},
	}

	var firstIPv6 string
	for _, ep := range endpoints {
		ip := fetchIP(client, ep.url, ep.parse)
		if ip == "" {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			logger.Infof("public IP detected via %s: %s", ep.url, ip)
			return ip
		}
		if firstIPv6 == "" {
			firstIPv6 = ip
			logger.Infof("public IPv6 detected via %s: %s", ep.url, ip)
		}
	}
	return firstIPv6
}

const publicIPConfigHint = "configure public IP via one of:\n" +
	"  1. Environment variable:  export PUBLIC_IP=<ip>\n" +
	"  2. Command-line flag:     --public <ip>\n" +
	"  3. Config file:           node.public_address: <ip>\n" +
	"  4. Startup config:        node.public_address in --startup.config_b64"

// resolvePublicAddress 阻塞式解析公网 IP：顺序检测 → 失败则循环重试直到获取
// 交互 TTY 模式下允许用户手动输入；非交互模式后台持续重试
func resolvePublicAddress(cfg *config.Config) (string, error) {
	// 1. 显式配置优先
	candidate := strings.TrimSpace(os.Getenv("PUBLIC_IP"))
	if candidate == "" {
		candidate = strings.TrimSpace(publicAddr)
	}
	if candidate == "" {
		candidate = strings.TrimSpace(cfg.Node.PublicAddress)
	}
	if candidate != "" {
		return validatePublicAddress(candidate)
	}

	// 2. 顺序自动检测
	logger.Infof("detecting public IP address sequentially...")
	if ip := detectPublicIPSequential(); ip != "" {
		return ip, nil
	}

	// 3. 检测失败 — 阻塞重试直到获取到公网 IP
	for {
		logger.Warnf("public IP address not detected; Edge requires a reachable public address for TLS certificates and client connections.\n%s", publicIPConfigHint)

		if isStdinTerminal() {
			// 交互模式：提示用户输入或按 Enter 重试
			fmt.Printf("\n⚠️  Public IP not detected. Edge cannot start without a public address.\n")
			fmt.Printf("   Press Enter to retry detection, or type a public IP/domain: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				input := strings.TrimSpace(scanner.Text())
				if input != "" {
					if addr, validateErr := validatePublicAddress(input); validateErr == nil {
						return addr, nil
					} else {
						fmt.Printf("   Invalid address: %v\n", validateErr)
					}
				}
			}
		} else {
			// 非交互模式：等待后重试
			time.Sleep(10 * time.Second)
		}

		// 重试检测
		if ip := detectPublicIPSequential(); ip != "" {
			return ip, nil
		}
	}
}

// ensurePublicAddress 确保 cfg.Node.PublicAddress 已设置
// 在 startup config 和命令行参数两条路径之后统一调用
func ensurePublicAddress(cfg *config.Config) error {
	if strings.TrimSpace(cfg.Node.PublicAddress) != "" {
		return nil
	}
	resolved, err := resolvePublicAddress(cfg)
	if err != nil {
		return fmt.Errorf("resolve public address: %w", err)
	}
	if resolved != "" {
		cfg.Node.PublicAddress = resolved
		logger.Infof("public address resolved: %s", resolved)
	}
	return nil
}

// detectPublicIPs 并发获取公网 IPv4 和 IPv6 地址
// 使用多个服务并发请求，500ms 超时
func detectPublicIPs() []string {
	type ipResult struct {
		ip      string
		isIPv6  bool
		service string
	}

	// IPv4 检测服务
	ipv4Services := []struct {
		url   string
		parse func([]byte) string
	}{
		{"https://ip-query.com/api/myip", func(b []byte) string {
			var ip = struct {
				IP string `json:"ip"`
			}{}
			if err := json.Unmarshal(b, &ip); err != nil {
				logger.Warnf("ip query get ip fail, %v", err)
			}
			return ip.IP
		}},
		{"https://api.ipify.org", func(b []byte) string { return strings.TrimSpace(string(b)) }},
		{"https://ipv4.icanhazip.com", func(b []byte) string { return strings.TrimSpace(string(b)) }},
		{"https://v4.ident.me", func(b []byte) string { return strings.TrimSpace(string(b)) }},
	}

	// IPv6 检测服务
	ipv6Services := []struct {
		url   string
		parse func([]byte) string
	}{
		{"https://api6.ipify.org", func(b []byte) string { return strings.TrimSpace(string(b)) }},
		{"https://ipv6.icanhazip.com", func(b []byte) string { return strings.TrimSpace(string(b)) }},
		{"https://v6.ident.me", func(b []byte) string { return strings.TrimSpace(string(b)) }},
	}

	results := make(chan ipResult, len(ipv4Services)+len(ipv6Services))
	timeout := 1000 * time.Millisecond

	// 创建带超时的 HTTP 客户端
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
		},
	}

	// 并发请求 IPv4
	for _, svc := range ipv4Services {
		go func(url string, parse func([]byte) string) {
			if ip := fetchIP(client, url, parse); ip != "" && net.ParseIP(ip) != nil {
				results <- ipResult{ip: ip, isIPv6: false, service: url}
			}
		}(svc.url, svc.parse)
	}

	// 并发请求 IPv6
	for _, svc := range ipv6Services {
		go func(url string, parse func([]byte) string) {
			if ip := fetchIP(client, url, parse); ip != "" && net.ParseIP(ip) != nil {
				results <- ipResult{ip: ip, isIPv6: true, service: url}
			}
		}(svc.url, svc.parse)
	}

	// 收集结果，等待超时
	var ipv4, ipv6 string
	timer := time.NewTimer(timeout + 50*time.Millisecond) // 额外 50ms 缓冲
	defer timer.Stop()

	for {
		select {
		case r := <-results:
			if r.isIPv6 && ipv6 == "" {
				ipv6 = r.ip
			} else if !r.isIPv6 && ipv4 == "" {
				ipv4 = r.ip
			}
			// 如果两个都获取到了，提前返回
			if ipv4 != "" && ipv6 != "" {
				return buildIPList(ipv4, ipv6)
			}
		case <-timer.C:
			return buildIPList(ipv4, ipv6)
		}
	}
}

// fetchIP 从指定 URL 获取 IP 地址
func fetchIP(client *http.Client, url string, parse func([]byte) string) string {
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return ""
	}

	return parse(body)
}

// buildIPList 构建 IP 列表，IPv4 优先
func buildIPList(ipv4, ipv6 string) []string {
	var ips []string
	if ipv4 != "" {
		ips = append(ips, ipv4)
	}
	if ipv6 != "" {
		ips = append(ips, ipv6)
	}
	return ips
}

func validatePublicAddress(input string) (string, error) {
	if strings.Contains(input, "://") {
		return "", fmt.Errorf("must not include scheme (e.g. http://)")
	}

	// public_address 不应包含端口，只能是 IP 或域名
	if strings.Contains(input, ":") {
		return "", fmt.Errorf("public address must not include port (only IP or domain allowed)")
	}

	host := input

	// 不允许通配符地址
	if host == "0.0.0.0" || host == "::" {
		return "", fmt.Errorf("must not be a wildcard address (0.0.0.0 or ::)")
	}

	// 验证是否为有效 IP
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	// 验证是否为有效域名
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^localhost$`)
	if domainRegex.MatchString(host) {
		return host, nil
	}

	return "", fmt.Errorf("invalid public address '%s': must be a valid IP or domain (without port)", host)
}

func normalizeDNSName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

// buildCertChecker returns a CertChecker that checks if a valid cert file exists on disk.
// Returns nil if HTTPS is not configured.
func buildCertChecker(cfg *config.Config) config.CertChecker {
	if cfg == nil || cfg.Proxy.HTTP == nil || cfg.Proxy.HTTP.HTTPSPort == 0 {
		return nil
	}
	certDir := filepath.Join(cfg.GetDataDir(), "custome_certs")
	return func(domain string) bool {
		base := sanitizeDomainForCertFile(domain)
		certPath := filepath.Join(certDir, base+".crt")
		keyPath := filepath.Join(certDir, base+".key")
		_, certErr := os.Stat(certPath)
		_, keyErr := os.Stat(keyPath)
		return certErr == nil && keyErr == nil
	}
}

func sanitizeDomainForCertFile(domain string) string {
	domain = normalizeDNSName(domain)
	if domain == "" {
		return "unknown"
	}
	var b strings.Builder
	b.Grow(len(domain))
	for i := 0; i < len(domain); i++ {
		ch := domain[i]
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteByte(ch)
		case ch >= '0' && ch <= '9':
			b.WriteByte(ch)
		case ch == '.', ch == '-':
			b.WriteByte(ch)
		case ch == '*':
			b.WriteString("wildcard")
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func logDomainStatus(cfg *config.Config) {
	as := cfg.Channel.DomainConfig.GetAssignedDomainStatus()
	cs := cfg.Channel.DomainConfig.GetCustomDomainStatus()
	cname := cfg.Channel.DomainConfig.GetCnameStatus()

	if cfg.Channel.GetAssignedDomain() != "" {
		logger.Infof("domain status [assigned=%s]: dns=%d, cert=%d, err=%s",
			cfg.Channel.GetAssignedDomain(), as.DNSStatus, as.CertStatus, as.Error)
	}
	if cfg.Channel.GetCustomDomain() != "" {
		logger.Infof("domain status [custom=%s]: dns=%d, cert=%d, cname=%d, err=%s",
			cfg.Channel.GetCustomDomain(), cs.DNSStatus, cs.CertStatus, cname, cs.Error)
	}
}

// verifyCustomDomainCNAME 校验用户自定义域名是否通过 CNAME 指向 edge assignedDomain。
func verifyCustomDomainCNAME(customDomain, targetAssignedDomain string) (bool, error) {
	customDomain = normalizeDNSName(customDomain)
	targetAssignedDomain = normalizeDNSName(targetAssignedDomain)
	if customDomain == "" || targetAssignedDomain == "" {
		return false, fmt.Errorf("customDomain or targetAssignedDomain is empty")
	}

	// 优先检测随机子域，验证泛域 CNAME 是否生效。
	probeHost := fmt.Sprintf("yat-dns-check-%d.%s", time.Now().Unix(), customDomain)
	cname, err := net.LookupCNAME(probeHost)
	if err != nil {
		// 部分 DNS 只配置 apex，回退一次根域检测
		cname, err = net.LookupCNAME(customDomain)
		if err != nil {
			return false, fmt.Errorf("CNAME lookup failed for %s: %w", probeHost, err)
		}
	}

	cname = normalizeDNSName(cname)
	if cname == targetAssignedDomain || strings.HasSuffix(cname, "."+targetAssignedDomain) {
		return true, nil
	}

	return false, fmt.Errorf("CNAME resolved to %s, expected suffix %s", cname, targetAssignedDomain)
}

// resolveCustomDomain 处理 CustomDomain 的 DNS 校验
// 在非 daemon 模式下，如果 DNS 未解析，会提示用户手动解析并可跳过
func resolveCustomDomain(cfg *config.Config) error {
	customDomain := cfg.Channel.GetCustomDomain()
	targetAssignedDomain := cfg.Channel.GetAssignedDomain()
	msg := i18n.Msg()

	// 如果没有设置 CustomDomain，跳过校验
	if customDomain == "" {
		return nil
	}

	// 无系统 assignedDomain 时无法进行 CNAME 校验
	if targetAssignedDomain == "" {
		logger.Warn(msg.CannotVerifyDNS)
		return nil
	}

	fmt.Println(msg.VerifyingDNS)
	fmt.Printf(msg.AssignedDomainLabel+"\n", customDomain)
	fmt.Printf(msg.ExpectedResolve+"\n", fmt.Sprintf("%s", targetAssignedDomain))

	resolved, err := verifyCustomDomainCNAME(customDomain, targetAssignedDomain)
	if resolved {
		fmt.Println(msg.DNSCorrect)
		return nil
	}

	// DNS 未正确解析，提示用户
	fmt.Println(msg.DNSIncorrect)
	if err != nil {
		fmt.Printf(msg.ErrorLabel+"\n", err)
	}
	fmt.Println(msg.DNSRecordGuide)
	fmt.Println(msg.DNSRecordType)
	fmt.Printf(msg.DNSRecordName+"\n", customDomain)
	fmt.Printf(msg.DNSRecordValue+"\n", fmt.Sprintf("%s", targetAssignedDomain))
	fmt.Println(msg.DNSRecordTTL)

	// 非 daemon 模式下，允许用户选择跳过或重试
	// 但如果 stdin 不是终端（如 systemd、管道输入），则跳过交互直接警告
	if !daemonMode && isStdinTerminal() {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Println(msg.SelectOperation)
			fmt.Println(msg.OptionRetry)
			fmt.Println(msg.OptionSkip)
			fmt.Println(msg.OptionQuit)
			fmt.Print(msg.InputPrompt)

			if scanner.Scan() {
				input := strings.TrimSpace(strings.ToLower(scanner.Text()))
				switch input {
				case "r":
					resolved, err = verifyCustomDomainCNAME(customDomain, targetAssignedDomain)
					if resolved {
						fmt.Println(msg.DNSCorrect)
						return nil
					}
					fmt.Print(msg.DNSStillIncorrect)
					if err != nil {
						fmt.Printf(": %v", err)
					}
					fmt.Println()
				case "s":
					fmt.Println(msg.SkippingDNS)
					fmt.Println(msg.SkipNote)
					return nil
				case "q":
					return fmt.Errorf("%s", msg.UserCancelled)
				default:
					fmt.Print(msg.InvalidOptionRSQ)
				}
			} else {
				break
			}
		}
	} else {
		// daemon 模式或非交互终端（systemd/管道），只输出警告，不阻塞启动
		logger.Warn(msg.DNSStillIncorrect)
	}

	return nil
}

// getMode Get running mode
func getMode() string {
	if daemonMode {
		return "daemon"
	}
	return "foreground"
}

// markOnline Resume local channel services
func markOnline() error {
	return markLocalStatus("Resuming", func(c *ipc.Client) error {
		return c.MarkOnline()
	})
}

// markOffline Suspend local channel services
func markOffline() error {
	return markLocalStatus("Suspending", func(c *ipc.Client) error {
		return c.MarkOffline()
	})
}

// markLocalStatus Send a local lifecycle command
func markLocalStatus(action string, ipcFunc func(*ipc.Client) error) error {
	// 1. Check if service is running
	dmn := daemon.New(pidFile)
	running, pid, err := dmn.Status()
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	if !running {
		return fmt.Errorf("server is not running, please start the server first")
	}

	fmt.Printf("%s server (PID: %d)...\n", action, pid)

	// 2. Try to communicate with running service via IPC
	client := ipc.NewClient(sockFile)
	if err := ipcFunc(client); err != nil {
		logger.Warnf("IPC communication failed (sock=%s): %v", sockFile, err)
		return fmt.Errorf("ipc command failed (sock=%s): %w", sockFile, err)
	}

	return nil
}
