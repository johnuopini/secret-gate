package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/johnuopini/secret-gate/internal/config"
	"github.com/johnuopini/secret-gate/internal/handlers"
	"github.com/johnuopini/secret-gate/internal/logger"
	"github.com/johnuopini/secret-gate/internal/models"
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
	mux.HandleFunc("/health", h.HandleHealth)
	mux.HandleFunc("/_/health", h.HandleHealth) // OpenFaaS watchdog health check path
	mux.HandleFunc("/request", h.HandleRequest)
	mux.HandleFunc("/search", h.HandleSearch)
	mux.HandleFunc("/fields", h.HandleFields)
	mux.HandleFunc("/status/", h.HandleStatus)
	mux.HandleFunc("/secret/", h.HandleSecret)
	mux.HandleFunc("/client/", h.HandleClientDownload)
	mux.HandleFunc("/openapi.json", h.HandleOpenAPI)
	mux.HandleFunc("/", handleRoot)

	// Start Telegram polling goroutine
	go tgClient.PollUpdates(func(callback *telegram.CallbackQuery) {
		parts := strings.SplitN(callback.Data, ":", 2)
		if len(parts) != 2 {
			tgClient.AnswerCallbackQuery(callback.ID, "Invalid callback data")
			return
		}

		action := parts[0]
		requestID := parts[1]

		req, err := requestStore.GetByID(requestID)
		if err == store.ErrNotFound {
			tgClient.AnswerCallbackQuery(callback.ID, "Request not found or expired")
			return
		}
		if err != nil {
			log.Error("Error fetching request", logger.F("error", err.Error(), "request_id", requestID))
			tgClient.AnswerCallbackQuery(callback.ID, "Internal error")
			return
		}

		if req.Status != models.StatusPending {
			tgClient.AnswerCallbackQuery(callback.ID, "Request already processed")
			return
		}

		approver := callback.From.Username
		if approver == "" {
			approver = callback.From.FirstName
		}

		switch action {
		case "approve":
			req.Approve()
			if err := requestStore.Update(req); err != nil {
				log.Error("Error updating request", logger.F("error", err.Error(), "request_id", req.ID))
			}
			tgClient.AnswerCallbackQuery(callback.ID, "Approved!")
			if req.TelegramMsgID != 0 {
				tgClient.UpdateMessageApproved(req.TelegramMsgID, req, approver)
			}
			log.Info("Request approved", logger.F("request_id", req.ID, "approver", approver))

		case "deny":
			req.Deny()
			if err := requestStore.Update(req); err != nil {
				log.Error("Error updating request", logger.F("error", err.Error(), "request_id", req.ID))
			}
			tgClient.AnswerCallbackQuery(callback.ID, "Denied")
			if req.TelegramMsgID != 0 {
				tgClient.UpdateMessageDenied(req.TelegramMsgID, req, approver)
			}
			log.Info("Request denied", logger.F("request_id", req.ID, "approver", approver))

		default:
			tgClient.AnswerCallbackQuery(callback.ID, "Unknown action")
		}
	})

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
