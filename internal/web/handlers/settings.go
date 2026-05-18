package handlers

import (
	"encoding/json"
	"net/http"
	"os"

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
		var s models.Setting
		db.DB.Where(models.Setting{Key: k}).FirstOrCreate(&s)
		s.Value = v
		db.DB.Save(&s)
	}
	GetSettings(w, r)
}
