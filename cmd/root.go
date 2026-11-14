/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"icool.io/yat/edge/pkg/config"
	"icool.io/yat/edge/pkg/log"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "edge",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Set log level based on flag
		switch strings.ToLower(logLevel) {
		case "debug":
			log.DefaultLogger.SetLevel(logrus.DebugLevel)
		case "info":
			log.DefaultLogger.SetLevel(logrus.InfoLevel)
		case "warn", "warning":
			log.DefaultLogger.SetLevel(logrus.WarnLevel)
		case "error":
			log.DefaultLogger.SetLevel(logrus.ErrorLevel)
		default:
			log.DefaultLogger.SetLevel(logrus.InfoLevel)
		}
	},
}

var dataDir string
var logLevel string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "show edge server version info",
	Long:  `Show version, build and commit information of edge server`,
	Run: func(cmd *cobra.Command, args []string) {
		version, build, commit, rt := config.GetVersionInfo()
		fmt.Printf("Version: %s\n", version)
		fmt.Printf("Build:   %s\n", build)
		fmt.Printf("Commit:  %s\n", commit)
		fmt.Printf("Runtime:  %s\n", rt)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.edge.yaml)")
	rootCmd.PersistentFlags().StringVar(
		&dataDir,
		"data",
		"",
		fmt.Sprintf("data directory path (default: %s)", config.DefaultDataDir()),
	)
	rootCmd.PersistentFlags().StringVar(
		&logLevel,
		"log-level",
		"info",
		"log level (debug, info, warn, error)",
	)

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.AddCommand(versionCmd)
}
