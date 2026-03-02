package daemon

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// RunDaemon is the entrypoint for the background daemon process.
// It writes a PID file, starts the server, and auto-exits when idle.
func RunDaemon(socketPath string, cacheTTLSeconds int, idleTimeoutSeconds int) error {
	cacheTTL := time.Duration(cacheTTLSeconds) * time.Second
	idleTimeout := time.Duration(idleTimeoutSeconds) * time.Second

	// Write PID file
	pidFile := PIDFilePath()
	if err := WritePIDFile(pidFile); err != nil {
		return fmt.Errorf("writing PID file: %w", err)
	}
	defer os.Remove(pidFile)

	srv := NewServer(socketPath, cacheTTL)

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run()
	}()

	// Idle monitor — check periodically if cache is empty
	idleTicker := time.NewTicker(30 * time.Second)
	defer idleTicker.Stop()
	lastActivity := time.Now()

	for {
		select {
		case err := <-errCh:
			return err
		case <-sigCh:
			srv.Stop()
			return nil
		case <-idleTicker.C:
			if srv.cache.HasValidEntries() {
				lastActivity = time.Now()
			} else if time.Since(lastActivity) > idleTimeout {
				srv.Stop()
				return nil
			}
		}
	}
}
