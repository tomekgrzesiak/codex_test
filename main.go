package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	googleauth "demo/internal/auth/google"
	"demo/internal/config"
	"demo/internal/petstore"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)

	if cfg.Database.DSN == "" {
		log.Fatal("database.dsn configuration is required")
	}

	pool, err := pgxpool.New(context.Background(), cfg.Database.DSN)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer pool.Close()

	repo, err := petstore.NewPostgresRepository(context.Background(), pool)
	if err != nil {
		log.Fatalf("failed to initialize pet repository: %v", err)
	}

	serverImpl := petstore.NewServer(repo)

	if cfg.GoogleOAuth.Enabled {
		googleHandler, err := googleauth.NewHandler(cfg.GoogleOAuth)
		if err != nil {
			log.Fatalf("failed to initialize google oauth handler: %v", err)
		}
		router.Group(func(r chi.Router) {
			r.Get("/auth/google/login", googleHandler.Login)
			r.Get("/auth/google/callback", googleHandler.Callback)
		})
	}

	handler := petstore.HandlerFromMux(serverImpl, router)

	addr := cfg.Server.Address
	if addr == "" {
		addr = ":8080"
	}

	httpServer := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	go func() {
		log.Printf("event=server_listen addr=%q pid=%d", addr, os.Getpid())
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	log.Println("Shutdown signal received, closing server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("graceful shutdown failed: %v", err)
	}

	log.Println("Server exited cleanly")
}
