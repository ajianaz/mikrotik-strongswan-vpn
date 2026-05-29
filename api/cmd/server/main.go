package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/ajianaz/vpn-manager/internal/config"
	"github.com/ajianaz/vpn-manager/internal/db"
	"github.com/ajianaz/vpn-manager/internal/handler"
	apimw "github.com/ajianaz/vpn-manager/internal/middleware"
	"github.com/ajianaz/vpn-manager/internal/service"
	"github.com/ajianaz/vpn-manager/internal/strongswan"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Initialize database pool
	ctx := context.Background()
	pool, err := db.NewPool(ctx, cfg.DBURL)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close(pool)
	slog.Info("connected to database")

	// Migrate database
	if err := db.Migrate(ctx, pool); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	// Setup services
	swanCfg := strongswan.Config{
		ContainerName:  cfg.VPNContainer,
		ConfigDir:      cfg.VPNConfigDir,
		SecretFile:     cfg.VPNSecretFile,
		L2TPSecretFile: cfg.VPNL2TPSecretFile,
	}
	svc := service.NewService(pool, swanCfg, cfg.EncryptionKey)
	h := handler.NewHandler(svc)

	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(apimw.APIKeyAuth(cfg.APIKey))

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Mount("/tunnels", h.Routes())
		r.Post("/reload", h.ReloadAll)
	})

	// Start HTTP server
	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("starting server", "listen", cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("shutting down", "signal", sig.String())

	// Graceful shutdown with 15s timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server forced shutdown", "error", err)
	}

	slog.Info("server stopped")
}
