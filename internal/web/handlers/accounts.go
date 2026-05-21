package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db/models"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/gmail"
)

func ListAccounts(w http.ResponseWriter, r *http.Request) {
	var accounts []models.Account
	db.DB.Find(&accounts)
	writeJSON(w, accounts)
}

func StartOAuth(w http.ResponseWriter, r *http.Request) {
	url, err := gmail.StartOAuth()
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"url": url})
}

func DeleteAccount(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := db.DB.Delete(&models.Account{}, id).Error; err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func PreviewGmailQuery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccountID uint   `json:"account_id"`
		Query     string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}
	var acct models.Account
	if err := db.DB.First(&acct, req.AccountID).Error; err != nil {
		writeError(w, "account not found", http.StatusNotFound)
		return
	}
	client, err := gmail.GmailServiceForAccount(r.Context(), &acct)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ids, err := client.SearchMessages(r.Context(), req.Query)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	limit := 10
	if len(ids) < limit {
		limit = len(ids)
	}
	type preview struct {
		ID      string `json:"id"`
		Subject string `json:"subject"`
		Sender  string `json:"sender"`
		Date    string `json:"date"`
	}
	var results []preview
	for _, id := range ids[:limit] {
		msg, err := client.FetchMessage(r.Context(), id)
		if err != nil {
			continue
		}
		results = append(results, preview{
			ID:      id,
			Subject: msg.Subject,
			Sender:  msg.Sender,
			Date:    msg.Date.Format("2006-01-02"),
		})
	}
	writeJSON(w, results)
}
