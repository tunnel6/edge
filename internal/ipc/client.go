package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)


type Client struct {
	socketPath string
}

// NewClient creates an IPC client.
//
// Backward compatible behavior:
// - when input ends with ".sock", treat it as a socket path directly;
// - otherwise treat input as pid-file path and derive "<pid-file>.sock".
func NewClient(path string) *Client {
	socketPath := strings.TrimSpace(path)
	if filepath.Ext(socketPath) != ".sock" {
		dir := filepath.Dir(socketPath)
		base := filepath.Base(socketPath)
		socketPath = filepath.Join(dir, base+".sock")
	}

	return &Client{
		socketPath: socketPath,
	}
}

// Send
func (c *Client) SendCommand(cmd string, params map[string]interface{}) (*Response, error) {
	// Check
	if _, err := os.Stat(c.socketPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("service is not running or IPC socket not found")
	}

	
	conn, err := net.DialTimeout("unix", c.socketPath, Timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to service: %w", err)
	}
	defer conn.Close()

	
	req := Request{
		Command: cmd,
		Params:  params,
	}

	// Send
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(&req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	
	var resp Response
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("receive response: %w", err)
	}

	return &resp, nil
}


func (c *Client) MarkOnline() error {
	resp, err := c.SendCommand("online", nil)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("mark online failed: %s", resp.Message)
	}

	return nil
}


func (c *Client) MarkOffline() error {
	resp, err := c.SendCommand("offline", nil)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("mark offline failed: %s", resp.Message)
	}

	return nil
}

// Config
func (c *Client) Reload() error {
	resp, err := c.SendCommand("reload", nil)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("reload failed: %s", resp.Message)
	}

	return nil
}

// Get
func (c *Client) GetStatus() (*Response, error) {
	return c.SendCommand("status", nil)
}
