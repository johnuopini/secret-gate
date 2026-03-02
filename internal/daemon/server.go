package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type Server struct {
	socketPath string
	cache      *Cache
	cacheTTL   time.Duration
	startedAt  time.Time
	listener   net.Listener
	stopCh     chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
}

func NewServer(socketPath string, cacheTTL time.Duration) *Server {
	return &Server{
		socketPath: socketPath,
		cache:      NewCache(),
		cacheTTL:   cacheTTL,
		startedAt:  time.Now(),
		stopCh:     make(chan struct{}),
	}
}

func (s *Server) Run() error {
	os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = ln

	if err := os.Chmod(s.socketPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	s.wg.Add(1)
	go s.cleanupLoop()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return nil
			default:
				continue
			}
		}
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		if s.listener != nil {
			s.listener.Close()
		}
		os.Remove(s.socketPath)
	})
	s.wg.Wait()
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}

	var req Request
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		s.writeResponse(conn, Response{Error: "invalid request"})
		return
	}

	resp := s.handleRequest(req)
	s.writeResponse(conn, resp)
}

func (s *Server) handleRequest(req Request) Response {
	switch req.Command {
	case CmdGet:
		return s.handleGet(req)
	case CmdStore:
		return s.handleStore(req)
	case CmdList:
		return s.handleList()
	case CmdFlush:
		return s.handleFlush()
	case CmdStatus:
		return s.handleStatus()
	case CmdStop:
		go func() {
			time.Sleep(100 * time.Millisecond)
			s.Stop()
		}()
		return Response{OK: true}
	default:
		return Response{Error: fmt.Sprintf("unknown command: %s", req.Command)}
	}
}

func (s *Server) handleGet(req Request) Response {
	entry, ok := s.cache.Get(req.SecretName, req.Vault)
	if !ok {
		return Response{OK: false, Error: "cache miss"}
	}
	return Response{OK: true, Fields: entry.Fields}
}

func (s *Server) handleStore(req Request) Response {
	ttl := s.cacheTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	s.cache.Store(req.SecretName, req.Vault, req.Fields, ttl)
	return Response{OK: true}
}

func (s *Server) handleList() Response {
	return Response{OK: true, Entries: s.cache.List()}
}

func (s *Server) handleFlush() Response {
	s.cache.Flush()
	return Response{OK: true}
}

func (s *Server) handleStatus() Response {
	return Response{
		OK: true,
		Status: &DaemonStatus{
			Uptime:     time.Since(s.startedAt).Truncate(time.Second).String(),
			EntryCount: s.cache.Count(),
			SocketPath: s.socketPath,
			PID:        os.Getpid(),
		},
	}
}

func (s *Server) writeResponse(conn net.Conn, resp Response) {
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	conn.Write(data)
}

func (s *Server) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.cache.Cleanup()
		}
	}
}
