//go:build windows

package daemon

import (
	"os"
	"os/signal"

	logger "icool.io/yat/edge/pkg/log"
)

// Start begins listening for signals
func (h *SignalHandler) Start() {
	h.signalChan = make(chan os.Signal, 1)
	signal.Notify(h.signalChan, os.Interrupt)
	go h.handleSignals()
}

func (h *SignalHandler) handleSignals() {
	for sig := range h.signalChan {
		logger.Infof("received signal: %v", sig)

		if sig == os.Interrupt {
			logger.Info("shutting down...")
			h.cleanup()
			os.Exit(0)
		}
	}
}
