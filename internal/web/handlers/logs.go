package handlers

import (
	"net/http"
	"strconv"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db/models"
)

func ListLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit < 1 || limit > 200 {
		limit = 25
	}
	offset := (page - 1) * limit

	tx := db.DB.Model(&models.RunLog{}).Order("started_at desc")
	if v := q.Get("account_id"); v != "" {
		tx = tx.Where("account_id = ?", v)
	}
	if v := q.Get("rule_id"); v != "" {
		tx = tx.Where("rule_id = ?", v)
	}
	if v := q.Get("status"); v != "" {
		tx = tx.Where("status = ?", v)
	}

	var total int64
	if err := tx.Count(&total).Error; err != nil {
		writeError(w, "database error", http.StatusInternalServerError)
		return
	}

	var logs []models.RunLog
	if err := tx.Limit(limit).Offset(offset).Find(&logs).Error; err != nil {
		writeError(w, "database error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{
		"total": total,
		"page":  page,
		"limit": limit,
		"items": logs,
	})
}
