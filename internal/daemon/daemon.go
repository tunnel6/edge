package daemon

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"

	"icool.io/yat/edge/pkg/config"
	logger "icool.io/yat/edge/pkg/log"
)

var (
	DefaultPidFile  = filepath.Join(config.DefaultDataDir(), "RUNNING")
	DefaultSockFile = filepath.Join(config.DefaultDataDir(), ".edge.sock")
)

type Daemon struct {
	pidFile string
}

// New creates a new Daemon instance
func New(pidFile string) *Daemon {
	if pidFile == "" {
		pidFile = DefaultPidFile
	}
	return &Daemon{
		pidFile: pidFile,
	}
}

// WritePid writes the current process PID to file
func (d *Daemon) WritePid() error {
	pid := os.Getpid()

	dir := filepath.Dir(d.pidFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create pid dir: %w", err)
	}

	if err := os.WriteFile(d.pidFile, []byte(fmt.Sprintf("%d\n", pid)), 0644); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}

	logger.Infof("pid file created path:[%s] pid:[%d]", d.pidFile, pid)
	return nil
}

// RemovePid removes the PID file
func (d *Daemon) RemovePid() error {
	if err := os.Remove(d.pidFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove pid file: %w", err)
	}
	logger.Infof("pid file removed: %s", d.pidFile)
	return nil
}

// ReadPid reads the PID from file
func (d *Daemon) ReadPid() (int, error) {
	data, err := os.ReadFile(d.pidFile)
	if err != nil {
		return 0, err
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("parse pid: %w", err)
	}

	return pid, nil
}

// Status returns the daemon status
func (d *Daemon) Status() (running bool, pid int, err error) {
	pid, err = d.ReadPid()
	if err != nil {
		if os.IsNotExist(err) {
			return false, 0, nil
		}
		return false, 0, err
	}

	running = d.IsRunning()
	return running, pid, nil
}

// GetPidFile returns the PID file path
func (d *Daemon) GetPidFile() string {
	return d.pidFile
}

// SignalHandler handles OS signals
type SignalHandler struct {
	daemon     *Daemon
	stopFunc   func() error
	reloadFunc func() error
	signalChan chan os.Signal
}

// NewSignalHandler creates a new signal handler
func NewSignalHandler(daemon *Daemon, stopFunc, reloadFunc func() error) *SignalHandler {
	return &SignalHandler{
		daemon:     daemon,
		stopFunc:   stopFunc,
		reloadFunc: reloadFunc,
		signalChan: make(chan os.Signal, 1),
	}
}

func (h *SignalHandler) cleanup() {
	if h.stopFunc != nil {
		if err := h.stopFunc(); err != nil {
			logger.Errorf("stop service failed: %v", err)
		}
	}
	if h.daemon != nil {
		if err := h.daemon.RemovePid(); err != nil {
			logger.Errorf("remove pid file failed: %v", err)
		}
	}
}

// Stop stops listening for signals
func (h *SignalHandler) Stop() {
	signal.Stop(h.signalChan)
	close(h.signalChan)
}
