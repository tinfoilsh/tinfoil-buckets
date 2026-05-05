package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/tinfoilsh/confidential-kv/config"
	"github.com/tinfoilsh/confidential-kv/handler"
	"github.com/tinfoilsh/confidential-kv/store"
)

func main() {
	cfg := config.Load()

	if cfg.CloudflareAccountID == "" || cfg.CloudflareAPIToken == "" {
		log.Fatal("CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN must be set")
	}

	r2 := store.NewR2Store(cfg.CloudflareAccountID, cfg.CloudflareAPIToken, cfg.CloudflareAPIToken, cfg.R2BucketName)

	kvHandler := handler.NewKVHandler(r2)

	mux := http.NewServeMux()
	mux.Handle("/kv/", kvHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	httpServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Infof("Starting confidential-kv server on %s", cfg.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-sigChan
	log.Info("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpServer.Shutdown(ctx)
}
