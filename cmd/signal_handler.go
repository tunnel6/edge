package cmd

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"icool.io/yat/edge/internal/daemon"
	logger "icool.io/yat/edge/pkg/log"
)

// SignalHandler Signal handler
type SignalHandler struct {
	pidFile string
	sigCh   chan os.Signal
}

// NewSignalHandler Create signal handler
func NewSignalHandler(pidFile string) *SignalHandler {
	return &SignalHandler{
		pidFile: pidFile,
		sigCh:   make(chan os.Signal, 1),
	}
}

// Setup Setup signal handling
func (h *SignalHandler) Setup(server *EdgeServer) {
	signal.Notify(h.sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-h.sigCh
		logger.Infof("received signal: %v", sig)

		// Stop server with overall timeout safety net.
		// Even if individual components have their own timeouts,
		// this ensures the process always exits within a bounded time.
		stopDone := make(chan struct{})
		go func() {
			defer close(stopDone)
			server.Stop()
		}()

		select {
		case <-stopDone:
			logger.Info("server stopped cleanly")
		case <-time.After(10 * time.Second):
			logger.Warn("server stop timed out after 10s, forcing exit")
		}

		// Clean up PID file
		dmn := daemon.New(h.pidFile)
		dmn.RemovePid()

		os.Exit(0)
	}()
}

// Stop Stop signal handling
func (h *SignalHandler) Stop() {
	signal.Stop(h.sigCh)
	close(h.sigCh)
}
