package handlers

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/crypto"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db/models"
)

func GetSettings(w http.ResponseWriter, r *http.Request) {
	settings := map[string]string{
		"database_url": os.Getenv("DATABASE_URL"),
	}
	var rows []models.Setting
	db.DB.Find(&rows)
	for _, row := range rows {
		settings[row.Key] = row.Value
	}

	// Resolve Google OAuth fields: DB takes priority over env, secret is masked.
	if settings["google_client_id"] == "" {
		settings["google_client_id"] = os.Getenv("GOOGLE_CLIENT_ID")
	}
	if settings["google_redirect_url"] == "" {
		settings["google_redirect_url"] = os.Getenv("OAUTH_REDIRECT_URL")
	}
	if enc := settings["google_client_secret"]; enc != "" {
		// Return a placeholder so the UI knows a secret is already configured.
		settings["google_client_secret"] = "****"
	} else if envSecret := os.Getenv("GOOGLE_CLIENT_SECRET"); envSecret != "" {
		settings["google_client_secret"] = "****"
	}

	writeJSON(w, settings)
}

func UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}

	readonly := map[string]bool{"database_url": true}

	for k, v := range req {
		if readonly[k] {
			continue
		}
		// Skip the secret placeholder — user didn't change it.
		if k == "google_client_secret" && v == "****" {
			continue
		}
		// Encrypt the client secret before storing.
		if k == "google_client_secret" && v != "" {
			enc, err := crypto.Encrypt(v)
			if err != nil {
				writeError(w, "failed to encrypt client secret", http.StatusInternalServerError)
				return
			}
			v = enc
		}
		var s models.Setting
		db.DB.Where(models.Setting{Key: k}).FirstOrCreate(&s)
		s.Value = v
		db.DB.Save(&s)
	}
	GetSettings(w, r)
}

