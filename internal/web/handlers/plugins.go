package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db/models"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/plugin"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/plugin/subprocess"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/plugin/webhook"
)

func ListPlugins(w http.ResponseWriter, r *http.Request) {
	var plugins []models.PluginConfig
	db.DB.Find(&plugins)
	writeJSON(w, plugins)
}

func CreatePlugin(w http.ResponseWriter, r *http.Request) {
	var p models.PluginConfig
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := db.DB.Create(&p).Error; err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, p)
}

func UpdatePlugin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var p models.PluginConfig
	if err := db.DB.First(&p, id).Error; err != nil {
		writeError(w, "not found", http.StatusNotFound)
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}
	db.DB.Save(&p)
	writeJSON(w, p)
}

func DeletePlugin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := db.DB.Delete(&models.PluginConfig{}, id).Error; err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func TestPlugin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var p models.PluginConfig
	if err := db.DB.First(&p, id).Error; err != nil {
		writeError(w, "not found", http.StatusNotFound)
		return
	}

	event := plugin.AttachmentEvent{
		RuleID:    0,
		Filename:  "test.pdf",
		NASPath:   "/test/test.pdf",
		SizeBytes: 1024,
		EmailDate: time.Now(),
		Subject:   "Test Event",
		Sender:    "test@example.com",
		MIMEType:  "application/pdf",
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var err error
	switch p.Type {
	case "webhook":
		var cfg webhook.Config
		json.Unmarshal([]byte(p.ConfigJSON), &cfg)
		err = webhook.New(p.Label, cfg).OnAttachmentSaved(ctx, event)
	case "subprocess":
		var cfg subprocess.Config
		json.Unmarshal([]byte(p.ConfigJSON), &cfg)
		var stdout bytes.Buffer
		_ = stdout
		err = subprocess.New(p.Label, cfg).OnAttachmentSaved(ctx, event)
	default:
		writeError(w, "unknown plugin type", http.StatusBadRequest)
		return
	}

	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
	} else {
		writeJSON(w, map[string]interface{}{"ok": true})
	}
}
