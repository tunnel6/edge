//go:build windows

package daemon

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/windows"

	logger "icool.io/yat/edge/pkg/log"
)

// Daemonize starts the process as a daemon
func (d *Daemon) Daemonize() error {
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

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)

	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false
	}
	return exitCode == 259 // STILL_ACTIVE
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

	if err := process.Kill(); err != nil {
		return fmt.Errorf("stop process: %w", err)
	}

	logger.Infof("stop signal sent, pid: %d", pid)
	return nil
}
