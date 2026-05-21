package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/crypto"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db/models"
	localfs "github.com/pacorreia/export-gmail-attachments-to-nas/internal/fileshare/local"
	smbfs "github.com/pacorreia/export-gmail-attachments-to-nas/internal/fileshare/smb"
)

func ListFileShares(w http.ResponseWriter, r *http.Request) {
	var fss []models.FileShare
	db.DB.Find(&fss)
	writeJSON(w, fss)
}

func CreateFileShare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label    string `json:"label"`
		Type     string `json:"type"`
		Host     string `json:"host"`
		Share    string `json:"share"`
		Username string `json:"username"`
		Password string `json:"password"`
		BasePath string `json:"base_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}
	enc := ""
	if req.Password != "" {
		var err error
		enc, err = crypto.Encrypt(req.Password)
		if err != nil {
			writeError(w, "encrypt: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	fs := models.FileShare{
		Label:       req.Label,
		Type:        req.Type,
		Host:        req.Host,
		Share:       req.Share,
		Username:    req.Username,
		PasswordEnc: enc,
		BasePath:    req.BasePath,
	}
	if err := db.DB.Create(&fs).Error; err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, fs)
}

func UpdateFileShare(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var fs models.FileShare
	if err := db.DB.First(&fs, id).Error; err != nil {
		writeError(w, "not found", http.StatusNotFound)
		return
	}
	var req struct {
		Label    string `json:"label"`
		Type     string `json:"type"`
		Host     string `json:"host"`
		Share    string `json:"share"`
		Username string `json:"username"`
		Password string `json:"password"`
		BasePath string `json:"base_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}
	fs.Label = req.Label
	fs.Type = req.Type
	fs.Host = req.Host
	fs.Share = req.Share
	fs.Username = req.Username
	fs.BasePath = req.BasePath
	if req.Password != "" {
		enc, err := crypto.Encrypt(req.Password)
		if err != nil {
			writeError(w, "encrypt: "+err.Error(), http.StatusInternalServerError)
			return
		}
		fs.PasswordEnc = enc
	}
	if err := db.DB.Save(&fs).Error; err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, fs)
}

func DeleteFileShare(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := db.DB.Delete(&models.FileShare{}, id).Error; err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// TestFileShareInline tests a connection using values from the request body,
// without requiring the file share to exist in the database first.
func TestFileShareInline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type     string `json:"type"`
		Host     string `json:"host"`
		Share    string `json:"share"`
		Username string `json:"username"`
		Password string `json:"password"`
		BasePath string `json:"base_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var testErr error
	switch req.Type {
	case "local":
		testErr = localfs.New(req.BasePath).Test(ctx)
	case "smb":
		testErr = smbfs.New(req.Host, req.Share, req.Username, req.Password).Test(ctx)
	default:
		writeError(w, "unknown type: "+req.Type, http.StatusBadRequest)
		return
	}

	if testErr == nil {
		writeJSON(w, map[string]interface{}{"ok": true})
	} else {
		writeJSON(w, map[string]interface{}{"ok": false, "error": testErr.Error()})
	}
}

func TestFileShare(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var fs models.FileShare
	if err := db.DB.First(&fs, id).Error; err != nil {
		writeError(w, "not found", http.StatusNotFound)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var testErr error
	switch fs.Type {
	case "local":
		testErr = localfs.New(fs.BasePath).Test(ctx)
	case "smb":
		password := ""
		if fs.PasswordEnc != "" {
			dec, err := crypto.Decrypt(fs.PasswordEnc)
			if err != nil {
				writeError(w, "decrypt: "+err.Error(), http.StatusInternalServerError)
				return
			}
			password = dec
		}
		testErr = smbfs.New(fs.Host, fs.Share, fs.Username, password).Test(ctx)
	default:
		writeError(w, "unknown type: "+fs.Type, http.StatusBadRequest)
		return
	}

	now := time.Now()
	ok := testErr == nil
	db.DB.Model(&fs).Updates(map[string]interface{}{
		"last_test_at": now,
		"last_test_ok": ok,
	})

	if ok {
		writeJSON(w, map[string]interface{}{"ok": true})
	} else {
		writeJSON(w, map[string]interface{}{"ok": false, "error": testErr.Error()})
	}
}
