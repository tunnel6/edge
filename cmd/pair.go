package cmd

import (
	"fmt"
	"net"

	"github.com/spf13/cobra"
	"icool.io/yat/edge/internal/daemon"
	"icool.io/yat/edge/internal/ipc"
	"icool.io/yat/edge/internal/upstream/certmgr"
	"icool.io/yat/edge/pkg/config"
)

var pairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Manage FE pairing (mTLS tunnel mode)",
	Long:  `Display pairing information for FE-to-Edge pairing via mTLS tunnel.`,
}

var pairGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a pairing token from the running Edge",
	Long: `Generate a one-time pairing token from the running Edge.

The token is valid for 1 hour and can only be used once.
The FE connects via the mTLS tunnel (not a separate HTTPS server).

The Edge must be running. Use --owner for management privileges.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Try to connect to running edge via IPC
		dmn := daemon.New(pidFile)
		running, _, statusErr := dmn.Status()
		if statusErr == nil && running {
			owner, _ := cmd.Flags().GetBool("owner")
			return getPairInfoFromIPC(owner)
		}

		// A token must be registered in the running Edge to be usable.
		return fmt.Errorf("Edge is not running; start it before generating a pairing token")
	},
}

var pairStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show pairing status",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig(configFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		dataDir := cfg.GetDataDir()

		// Check if certificates exist
		bundle, err := certmgr.NewManager(&certmgr.ManagerConfig{
			CertDir: dataDir,
		}).LoadCertificateBundle()

		if err != nil {
			fmt.Println("Status: NOT INITIALIZED")
			fmt.Println("  No certificates found. Run 'edge server start' first.")
			return nil
		}

		fmt.Println("Status: READY")
		fmt.Printf("  Edge ID:    %s\n", cfg.Node.ID)
		fmt.Printf("  CA CN:      %s\n", bundle.RootCACert.Subject.CommonName)
		fmt.Printf("  TLS Cert:   expires %s\n", bundle.TLSCert.NotAfter.Format("2006-01-02"))
		if bundle.SubCACert != nil {
			fmt.Printf("  CA Cert:    expires %s\n", bundle.SubCACert.NotAfter.Format("2006-01-02"))
		}

		// Show tunnel address
		tunnelAddr := resolveTunnelAddress(cfg)
		fmt.Printf("  Tunnel:     %s\n", tunnelAddr)
		fmt.Printf("  Pair mode:  mTLS tunnel (no separate pair server)\n")
		return nil
	},
}

// getPairInfoFromIPC connects to the running edge and retrieves pairing info.
func getPairInfoFromIPC(owner bool) error {
	client := ipc.NewClient(sockFile)
	resp, err := client.SendCommand("pair_info", map[string]interface{}{"owner": owner})
	if err != nil {
		return fmt.Errorf("connect to running edge (sock=%s): %w\nIs the edge server running?", sockFile, err)
	}
	if !resp.Success {
		return fmt.Errorf("pair_info failed: %s", resp.Message)
	}

	token, _ := resp.Data["token"].(string)
	tunnelAddr, _ := resp.Data["tunnel_address"].(string)
	edgeID, _ := resp.Data["edge_id"].(string)

	role, _ := resp.Data["role"].(string)
	fmt.Printf("Certificate role: %s\n", role)
	printPairInfo(tunnelAddr, token, edgeID)
	return nil
}

// resolveTunnelAddress constructs the public tunnel address from config.
func resolveTunnelAddress(cfg *config.Config) string {
	tunnelAddr := cfg.Tunnel.Listen
	if tunnelAddr == "" {
		tunnelAddr = "0.0.0.0:443"
	}
	if cfg.Node.PublicAddress != "" {
		if _, port, err := net.SplitHostPort(tunnelAddr); err == nil {
			tunnelAddr = net.JoinHostPort(cfg.Node.PublicAddress, port)
		}
	}
	return tunnelAddr
}

// printPairInfo displays the pairing information in a formatted box.
func printPairInfo(tunnelAddr, token, edgeID string) {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  YAT Edge Pairing Info (mTLS Tunnel)")
	fmt.Println("═══════════════════════════════════════════════════════")
	if edgeID != "" {
		fmt.Printf("  Edge ID:        %s\n", edgeID)
	}
	fmt.Printf("  Tunnel Address: %s\n", tunnelAddr)
	fmt.Printf("  Pairing Token:  %s\n", token)
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("  Open FE → Add Edge → Enter tunnel address and token")
	fmt.Println()
	fmt.Println("  Token valid for 1 hour, one-time use only.")
	fmt.Println()
}

func init() {
	rootCmd.AddCommand(pairCmd)
	pairCmd.AddCommand(pairGenerateCmd)
	pairCmd.AddCommand(pairStatusCmd)

	pairGenerateCmd.Flags().Bool("owner", false, "Grant Edge management privileges to the paired device")
	pairGenerateCmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	pairGenerateCmd.Flags().StringVar(&sockFile, "sock-file", daemon.DefaultSockFile, "sock file path")
	pairStatusCmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path")
	pairStatusCmd.Flags().StringVar(&sockFile, "sock-file", daemon.DefaultSockFile, "sock file path")
}
