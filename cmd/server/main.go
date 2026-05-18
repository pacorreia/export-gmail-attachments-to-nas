package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/scheduler"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/web"
)

func main() {
	if err := db.Open(); err != nil {
		log.Fatalf("open db: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sched := scheduler.Start(ctx)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: web.NewRouter(),
	}

	go func() {
		log.Println("Listening on :8080")
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
