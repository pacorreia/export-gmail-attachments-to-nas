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
	limit := 50
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
	tx.Count(&total)

	var logs []models.RunLog
	tx.Limit(limit).Offset(offset).Find(&logs)

	writeJSON(w, map[string]interface{}{
		"total": total,
		"page":  page,
		"items": logs,
	})
}
