//go:build !windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	logger "icool.io/yat/edge/pkg/log"
)

// Daemonize starts the process as a daemon
func (d *Daemon) Daemonize() error {
	if os.Getppid() == 1 {
		return nil
	}

	if d.IsRunning() {
		pid, _ := d.ReadPid()
		return fmt.Errorf("daemon already running with PID %d", pid)
	}

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	args := []string{}
	for _, arg := range os.Args[1:] {
		if arg != "-d" && arg != "--daemon" {
			args = append(args, arg)
		}
	}

	cmd := exec.Command(executable, args...)
	cmd.Env = os.Environ()
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start daemon process: %w", err)
	}

	logger.Infof("daemon started, pid: %d", cmd.Process.Pid)
	fmt.Printf("Daemon started with PID: %d\n", cmd.Process.Pid)

	os.Exit(0)
	return nil
}

// IsRunning checks if the daemon is running
func (d *Daemon) IsRunning() bool {
	pid, err := d.ReadPid()
	if err != nil {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

// Stop stops the running daemon
func (d *Daemon) Stop() error {
	pid, err := d.ReadPid()
	if err != nil {
		return fmt.Errorf("read pid: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process: %w", err)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("stop process: %w", err)
	}

	logger.Infof("stop signal sent, pid: %d", pid)
	return nil
}
