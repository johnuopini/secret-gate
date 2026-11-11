package main

import (
	"net/http"
	"time"

	"github.com/johnuopini/secret-gate/internal/config"
	"github.com/johnuopini/secret-gate/internal/handlers"
	"github.com/johnuopini/secret-gate/internal/logger"
	"github.com/johnuopini/secret-gate/internal/opconnect"
	"github.com/johnuopini/secret-gate/internal/store"
	"github.com/johnuopini/secret-gate/internal/telegram"
)

func main() {
	log := logger.New()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config", logger.F("error", err.Error()))
	}

	if err := cfg.Validate(); err != nil {
		log.Fatal("Invalid config", logger.F("error", err.Error()))
	}

	// Initialize components
	requestStore := store.New()
	opClient := opconnect.New(cfg.OPConnectHost, cfg.OPConnectToken)
	tgClient := telegram.New(cfg.TelegramBotToken, cfg.TelegramChatID)

	// Create HTTP handler
	h := handlers.New(requestStore, opClient, tgClient, cfg)

	// Set up routes
	mux := http.NewServeMux()
	h.Register(mux)
	mux.HandleFunc("/", handleRoot)

	// Start Telegram polling goroutine
	go tgClient.PollUpdates(h.HandleCallback)

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(cfg.CleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			if removed := requestStore.Cleanup(); removed > 0 {
				log.Info("Cleaned up expired requests", logger.F("removed", removed))
			}
		}
	}()

	log.Info("Starting secret-gate", logger.F("port", cfg.Port))
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatal("Failed to start server", logger.F("error", err.Error()))
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	// Only handle exact root path, let other paths 404
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"service": "secret-gate", "status": "running"}`))
}
