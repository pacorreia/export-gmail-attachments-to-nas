package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/crypto"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/scheduler"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/web"
)

func main() {
	if err := crypto.Init(os.Getenv("SECRET_KEY")); err != nil {
		log.Fatalf("crypto: %v", err)
	}

	if err := db.Open(); err != nil {
		log.Fatalf("open db: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sched := scheduler.Start(ctx)

	srv := &http.Server{
		Addr:    addr,
		Handler: web.NewRouter(),
	}

	go func() {
		log.Printf("Listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down...")
	srv.Shutdown(context.Background())
	sched.Stop()
	log.Println("Done")
}
