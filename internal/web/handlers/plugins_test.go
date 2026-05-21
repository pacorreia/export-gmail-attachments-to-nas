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

func clearPlugins(t *testing.T) {
	t.Helper()
	db.DB.Exec("DELETE FROM plugin_configs")
}

func TestListPlugins_Empty(t *testing.T) {
	clearPlugins(t)
	t.Cleanup(func() { clearPlugins(t) })

	req := httptest.NewRequest(http.MethodGet, "/api/plugins", nil)
	rr := httptest.NewRecorder()
	ListPlugins(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
	var list []models.PluginConfig
	decodeResponse(t, rr, &list)
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}
}

func TestCreatePlugin(t *testing.T) {
	clearPlugins(t)
	t.Cleanup(func() { clearPlugins(t) })

	body, _ := json.Marshal(models.PluginConfig{
		Label:      "my-webhook",
		Type:       "webhook",
		ConfigJSON: `{"url":"http://example.com","retries":3}`,
		Enabled:    true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/plugins", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	CreatePlugin(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
	var p models.PluginConfig
	decodeResponse(t, rr, &p)
	if p.Label != "my-webhook" {
		t.Errorf("label mismatch: %q", p.Label)
	}
}

func TestCreatePlugin_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/plugins", bytes.NewReader([]byte("{bad")))
	rr := httptest.NewRecorder()
	CreatePlugin(rr, req)
	assertStatusCode(t, rr, http.StatusBadRequest)
}

func TestUpdatePlugin(t *testing.T) {
	clearPlugins(t)
	t.Cleanup(func() { clearPlugins(t) })

	p := models.PluginConfig{Label: "old", Type: "webhook", ConfigJSON: `{"url":"http://a.com"}`}
	db.DB.Create(&p)

	updated, _ := json.Marshal(models.PluginConfig{Label: "new", Type: "webhook", ConfigJSON: `{"url":"http://b.com"}`})
	req := httptest.NewRequest(http.MethodPut, "/api/plugins/"+fmt.Sprint(p.ID), bytes.NewReader(updated))
	req = withURLParam(req, "id", fmt.Sprint(p.ID))
	rr := httptest.NewRecorder()
	UpdatePlugin(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
	var resp models.PluginConfig
	decodeResponse(t, rr, &resp)
	if resp.Label != "new" {
		t.Errorf("expected updated label, got %q", resp.Label)
	}
}

func TestUpdatePlugin_NotFound(t *testing.T) {
	body, _ := json.Marshal(models.PluginConfig{Label: "x"})
	req := httptest.NewRequest(http.MethodPut, "/api/plugins/9999", bytes.NewReader(body))
	req = withURLParam(req, "id", "9999")
	rr := httptest.NewRecorder()
	UpdatePlugin(rr, req)
	assertStatusCode(t, rr, http.StatusNotFound)
}

func TestDeletePlugin(t *testing.T) {
	clearPlugins(t)
	t.Cleanup(func() { clearPlugins(t) })

	p := models.PluginConfig{Label: "to-delete", Type: "webhook", ConfigJSON: "{}"}
	db.DB.Create(&p)

	req := httptest.NewRequest(http.MethodDelete, "/api/plugins/"+fmt.Sprint(p.ID), nil)
	req = withURLParam(req, "id", fmt.Sprint(p.ID))
	rr := httptest.NewRecorder()
	DeletePlugin(rr, req)
	assertStatusCode(t, rr, http.StatusNoContent)
}

func TestTestPlugin_Webhook(t *testing.T) {
	clearPlugins(t)
	t.Cleanup(func() { clearPlugins(t) })

	// Start a fake webhook target.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	p := models.PluginConfig{
		Label:      "webhook-test",
		Type:       "webhook",
		ConfigJSON: fmt.Sprintf(`{"url":"%s","retries":1}`, target.URL),
		Enabled:    true,
	}
	db.DB.Create(&p)

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/"+fmt.Sprint(p.ID)+"/test", nil)
	req = withURLParam(req, "id", fmt.Sprint(p.ID))
	rr := httptest.NewRecorder()
	TestPlugin(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
}

func TestTestPlugin_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/9999/test", nil)
	req = withURLParam(req, "id", "9999")
	rr := httptest.NewRecorder()
	TestPlugin(rr, req)
	assertStatusCode(t, rr, http.StatusNotFound)
}


