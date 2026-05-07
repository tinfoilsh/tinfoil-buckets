package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/tinfoilsh/tinfoil-buckets/identity"
	"github.com/tinfoilsh/tinfoil-buckets/config"
	"github.com/tinfoilsh/tinfoil-buckets/handler"
	"github.com/tinfoilsh/tinfoil-buckets/store"
	"github.com/tinfoilsh/tinfoil-buckets/usage"
)

func main() {
	cfg := config.Load()

	if cfg.CloudflareAccountID == "" || cfg.R2AccessKeyID == "" || cfg.R2SecretAccessKey == "" {
		log.Fatal("CLOUDFLARE_ACCOUNT_ID, R2_TINFOIL_BUCKET_ACCESS_KEY_ID, and R2_TINFOIL_BUCKET_SECRET_ACCESS_KEY must be set")
	}

	r2 := store.NewR2Store(cfg.CloudflareAccountID, cfg.R2AccessKeyID, cfg.R2SecretAccessKey, cfg.R2BucketName)
	resolver := identity.NewHTTPResolver(cfg.ControlPlaneURL)

	reporter, err := usage.NewReporter(cfg.ControlPlaneURL, cfg.UsageReporterID, cfg.UsageReporterSecret)
	if err != nil {
		log.Fatalf("Failed to create usage reporter: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := reporter.Close(ctx); err != nil {
			log.Warnf("usage reporter shutdown: %v", err)
		}
	}()

	itemHandler := handler.NewItemHandler(r2, resolver, reporter)

	mux := http.NewServeMux()
	mux.Handle("/items/", itemHandler)
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
		log.Infof("Starting tinfoil-buckets server on %s", cfg.ListenAddr)
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
