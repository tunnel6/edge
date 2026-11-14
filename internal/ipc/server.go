package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	logger "icool.io/yat/edge/pkg/log"
)

// Handle
type CommandHandler func(*Request) *Response


type Server struct {
	socketPath string
	listener   net.Listener
	handlers   map[string]CommandHandler
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// Create
func NewServer(sockPath string) *Server {

	if filepath.Ext(sockPath) != ".sock" {
		sockPath += ".sock"
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		socketPath: sockPath,
		handlers:   make(map[string]CommandHandler),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Handle
func (s *Server) RegisterHandler(command string, handler CommandHandler) {
	s.handlers[command] = handler
}

// Start
func (s *Server) Start() error {
	// Delete
	os.Remove(s.socketPath)

	// Create
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.socketPath, err)
	}
	s.listener = listener

	// Set
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		logger.Warnf("chmod socket file failed: %v", err)
	}

	// Start
	s.wg.Add(1)
	go s.acceptLoop()

	logger.Infof("IPC server started, socket: %s", s.socketPath)
	return nil
}

// Stop
func (s *Server) Stop() error {
	s.cancel()

	if s.listener != nil {
		s.listener.Close()
	}

	s.wg.Wait()

	// Delete
	os.Remove(s.socketPath)

	logger.Info("IPC server stopped")
	return nil
}


func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				logger.Errorf("accept error: %v", err)
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

// Handle
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Parse
	var req Request
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&req); err != nil {
		logger.Errorf("decode request failed: %v", err)
		s.sendError(conn, "invalid request")
		return
	}

	// Handle
	resp := s.handleCommand(&req)

	// Send
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(resp); err != nil {
		logger.Errorf("encode response failed: %v", err)
	}
}

// Handle
func (s *Server) handleCommand(req *Request) *Response {
	logger.Infof("IPC command received: %s", req.Command)

	handler, ok := s.handlers[req.Command]
	if !ok {
		return &Response{
			Success: false,
			Message: fmt.Sprintf("unknown command: %s", req.Command),
		}
	}

	return handler(req)
}

// Send
func (s *Server) sendError(conn net.Conn, message string) {
	resp := &Response{
		Success: false,
		Message: message,
	}
	encoder := json.NewEncoder(conn)
	encoder.Encode(resp)
}
