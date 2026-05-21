package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db/models"
)

func clearRules(t *testing.T) {
	t.Helper()
	db.DB.Exec("DELETE FROM rule_assignments")
	db.DB.Exec("DELETE FROM rules")
}

func createRuleBody(label string) []byte {
	b, _ := json.Marshal(map[string]any{
		"label":               label,
		"gmail_query":         "has:attachment",
		"subfolder_template":  "{year}",
		"convert_pdf_to_image": false,
		"enabled":             true,
	})
	return b
}

func TestListRules_Empty(t *testing.T) {
	clearRules(t)
	t.Cleanup(func() { clearRules(t) })

	req := httptest.NewRequest(http.MethodGet, "/api/rules", nil)
	rr := httptest.NewRecorder()
	ListRules(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
	var list []models.Rule
	decodeResponse(t, rr, &list)
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}
}

func TestCreateRule(t *testing.T) {
	clearRules(t)
	t.Cleanup(func() { clearRules(t) })

	req := httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader(createRuleBody("my-rule")))
	rr := httptest.NewRecorder()
	CreateRule(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
	var rule models.Rule
	decodeResponse(t, rr, &rule)
	if rule.Label != "my-rule" {
		t.Errorf("label mismatch: %q", rule.Label)
	}
	if rule.ID == 0 {
		t.Error("expected non-zero ID")
	}
}

func TestCreateRule_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader([]byte("{bad")))
	rr := httptest.NewRecorder()
	CreateRule(rr, req)
	assertStatusCode(t, rr, http.StatusBadRequest)
}

func TestUpdateRule(t *testing.T) {
	clearRules(t)
	t.Cleanup(func() { clearRules(t) })

	rule := models.Rule{Label: "original", GmailQuery: "q", Enabled: true}
	db.DB.Create(&rule)

	updated, _ := json.Marshal(map[string]any{
		"label":   "updated",
		"enabled": false,
	})
	req := httptest.NewRequest(http.MethodPut, "/api/rules/"+fmt.Sprint(rule.ID), bytes.NewReader(updated))
	req = withURLParam(req, "id", fmt.Sprint(rule.ID))
	rr := httptest.NewRecorder()
	UpdateRule(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
	var resp models.Rule
	decodeResponse(t, rr, &resp)
	if resp.Label != "updated" {
		t.Errorf("expected updated label, got %q", resp.Label)
	}
}

func TestUpdateRule_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/api/rules/9999",
		bytes.NewReader(createRuleBody("x")))
	req = withURLParam(req, "id", "9999")
	rr := httptest.NewRecorder()
	UpdateRule(rr, req)
	assertStatusCode(t, rr, http.StatusNotFound)
}

func TestDeleteRule(t *testing.T) {
	clearRules(t)
	t.Cleanup(func() { clearRules(t) })

	rule := models.Rule{Label: "to-delete"}
	db.DB.Create(&rule)

	req := httptest.NewRequest(http.MethodDelete, "/api/rules/"+fmt.Sprint(rule.ID), nil)
	req = withURLParam(req, "id", fmt.Sprint(rule.ID))
	rr := httptest.NewRecorder()
	DeleteRule(rr, req)
	assertStatusCode(t, rr, http.StatusNoContent)

	// GORM soft-deletes (sets deleted_at); verify the record is no longer accessible via normal queries.
	var count int64
	db.DB.Model(&models.Rule{}).Where("id = ?", rule.ID).Count(&count)
	if count != 0 {
		t.Error("rule should have been soft-deleted and not visible in normal queries")
	}
}

func TestGetRuleAssignments_Empty(t *testing.T) {
	clearRules(t)
	t.Cleanup(func() { clearRules(t) })

	rule := models.Rule{Label: "r"}
	db.DB.Create(&rule)

	req := httptest.NewRequest(http.MethodGet, "/api/rules/"+fmt.Sprint(rule.ID)+"/assignments", nil)
	req = withURLParam(req, "id", fmt.Sprint(rule.ID))
	rr := httptest.NewRecorder()
	GetRuleAssignments(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
	var assignments []models.RuleAssignment
	decodeResponse(t, rr, &assignments)
	if len(assignments) != 0 {
		t.Errorf("expected no assignments, got %d", len(assignments))
	}
}
