package handlers

import (
	"log"
	"os"
	"testing"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/crypto"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
)

func TestMain(m *testing.M) {
	if err := crypto.Init("handler-test-secret-key"); err != nil {
		log.Fatalf("crypto.Init: %v", err)
	}
	os.Setenv("DATABASE_URL", "sqlite://:memory:")
	if err := db.Open(); err != nil {
		log.Fatalf("db.Open: %v", err)
	}
	os.Exit(m.Run())
}
