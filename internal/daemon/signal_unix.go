//go:build !windows

package daemon

import (
	"os"
	"os/signal"
	"syscall"

	logger "icool.io/yat/edge/pkg/log"
)

// Start begins listening for signals
func (h *SignalHandler) Start() {
	h.signalChan = make(chan os.Signal, 1)
	signal.Notify(h.signalChan,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGHUP,
		syscall.SIGQUIT,
	)
	go h.handleSignals()
}

func (h *SignalHandler) handleSignals() {
	for sig := range h.signalChan {
		logger.Infof("received signal: %v", sig)

		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			logger.Info("shutting down...")
			h.cleanup()
			os.Exit(0)
		case syscall.SIGQUIT:
			logger.Info("graceful shutdown...")
			h.cleanup()
			os.Exit(0)
		case syscall.SIGHUP:
			logger.Info("reloading configuration...")
			if h.reloadFunc != nil {
				if err := h.reloadFunc(); err != nil {
					logger.Errorf("reload failed: %v", err)
				} else {
					logger.Info("configuration reloaded")
				}
			}
		}
	}
}
