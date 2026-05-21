package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db/models"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/scheduler"
)

func ListRules(w http.ResponseWriter, r *http.Request) {
	var rules []models.Rule
	db.DB.Find(&rules)
	writeJSON(w, rules)
}

func CreateRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label             string `json:"label"`
		GmailQuery        string `json:"gmail_query"`
		SubfolderTemplate string `json:"subfolder_template"`
		ConvertPDFToImage bool   `json:"convert_pdf_to_image"`
		Enabled           bool   `json:"enabled"`
		Schedule          string `json:"schedule"`
		DeleteAfterExport bool   `json:"delete_after_export"`
		AccountIDs        []uint `json:"account_ids"`
		FileShareIDs      []uint `json:"file_share_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}
	rule := models.Rule{
		Label:             req.Label,
		GmailQuery:        req.GmailQuery,
		SubfolderTemplate: req.SubfolderTemplate,
		ConvertPDFToImage: req.ConvertPDFToImage,
		Enabled:           req.Enabled,
		Schedule:          req.Schedule,
		DeleteAfterExport: req.DeleteAfterExport,
	}
	if err := db.DB.Create(&rule).Error; err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	saveAssignments(rule.ID, req.AccountIDs, req.FileShareIDs)
	if scheduler.Default != nil {
		scheduler.Default.Reload(rule.ID)
	}
	writeJSON(w, rule)
}

func UpdateRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var rule models.Rule
	if err := db.DB.First(&rule, id).Error; err != nil {
		writeError(w, "not found", http.StatusNotFound)
		return
	}
	var req struct {
		Label             string `json:"label"`
		GmailQuery        string `json:"gmail_query"`
		SubfolderTemplate string `json:"subfolder_template"`
		ConvertPDFToImage bool   `json:"convert_pdf_to_image"`
		Enabled           bool   `json:"enabled"`
		Schedule          string `json:"schedule"`
		DeleteAfterExport bool   `json:"delete_after_export"`
		AccountIDs        []uint `json:"account_ids"`
		FileShareIDs      []uint `json:"file_share_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request", http.StatusBadRequest)
		return
	}
	rule.Label = req.Label
	rule.GmailQuery = req.GmailQuery
	rule.SubfolderTemplate = req.SubfolderTemplate
	rule.ConvertPDFToImage = req.ConvertPDFToImage
	rule.Enabled = req.Enabled
	rule.Schedule = req.Schedule
	rule.DeleteAfterExport = req.DeleteAfterExport
	if err := db.DB.Save(&rule).Error; err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	db.DB.Where("rule_id = ?", rule.ID).Delete(&models.RuleAssignment{})
	saveAssignments(rule.ID, req.AccountIDs, req.FileShareIDs)
	if scheduler.Default != nil {
		scheduler.Default.Reload(rule.ID)
	}
	writeJSON(w, rule)
}

func ExecuteRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var rule models.Rule
	if err := db.DB.First(&rule, id).Error; err != nil {
		writeError(w, "not found", http.StatusNotFound)
		return
	}
	if err := scheduler.RunRuleNow(rule.ID); err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func DeleteRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var rule models.Rule
	if err := db.DB.First(&rule, id).Error; err != nil {
		writeError(w, "not found", http.StatusNotFound)
		return
	}
	if scheduler.Default != nil {
		scheduler.Default.StopRule(rule.ID)
	}
	db.DB.Where("rule_id = ?", rule.ID).Delete(&models.RuleAssignment{})
	db.DB.Where("rule_id = ?", rule.ID).Delete(&models.SyncCheckpoint{})
	if err := db.DB.Delete(&rule).Error; err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func GetRuleAssignments(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var assignments []models.RuleAssignment
	db.DB.Where("rule_id = ?", id).Find(&assignments)
	writeJSON(w, assignments)
}

// ToggleRule flips the enabled state of a rule and notifies the scheduler.
func ToggleRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var rule models.Rule
	if err := db.DB.First(&rule, id).Error; err != nil {
		writeError(w, "not found", http.StatusNotFound)
		return
	}
	rule.Enabled = !rule.Enabled
	if err := db.DB.Save(&rule).Error; err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if scheduler.Default != nil {
		if rule.Enabled {
			scheduler.Default.Reload(rule.ID)
		} else {
			scheduler.Default.StopRule(rule.ID)
		}
	}
	writeJSON(w, rule)
}

// ResetRuleCheckpoint deletes the sync checkpoint so the next run re-processes all matching messages.
func ResetRuleCheckpoint(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var rule models.Rule
	if err := db.DB.First(&rule, id).Error; err != nil {
		writeError(w, "not found", http.StatusNotFound)
		return
	}
	if err := scheduler.ResetCheckpoint(rule.ID); err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func saveAssignments(ruleID uint, accountIDs, fileShareIDs []uint) {
	for _, aid := range accountIDs {
		for _, fsid := range fileShareIDs {
			a := models.RuleAssignment{RuleID: ruleID, AccountID: aid, FileShareID: fsid}
			db.DB.Where(a).FirstOrCreate(&a)
		}
	}
}
