// Package e2e contains end-to-end tests that exercise the full HTTP stack:
// router → handlers → database, using an in-memory SQLite database and a
// real httptest.Server. No external services (Gmail, SMB) are contacted.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/crypto"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/web"
)

// server is the shared test server created in TestMain.
var server *httptest.Server

func TestMain(m *testing.M) {
	if err := crypto.Init("e2e-test-secret"); err != nil {
		log.Fatalf("crypto.Init: %v", err)
	}
	os.Setenv("DATABASE_URL", "sqlite://:memory:")
	if err := db.Open(); err != nil {
		log.Fatalf("db.Open: %v", err)
	}

	server = httptest.NewServer(web.NewRouter())
	defer server.Close()

	os.Exit(m.Run())
}

// helpers ─────────────────────────────────────────────────────────────────────

func apiURL(path string) string {
	return server.URL + path
}

func doJSON(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, apiURL(path), r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func assertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expected HTTP %d, got %d — body: %s", want, resp.StatusCode, body)
	}
}

// ─── File shares ──────────────────────────────────────────────────────────────

func TestFileShares_CRUD(t *testing.T) {
	dir := t.TempDir()

	// CREATE
	resp := doJSON(t, http.MethodPost, "/api/fileshares", map[string]any{
		"label":     "e2e-local",
		"type":      "local",
		"base_path": dir,
	})
	assertStatus(t, resp, http.StatusOK)
	var created map[string]any
	decodeJSON(t, resp, &created)
	id := created["id"]
	if id == nil {
		t.Fatal("expected id in response")
	}

	// LIST — should contain the new entry
	resp = doJSON(t, http.MethodGet, "/api/fileshares", nil)
	assertStatus(t, resp, http.StatusOK)
	var list []map[string]any
	decodeJSON(t, resp, &list)
	found := false
	for _, fs := range list {
		if fs["label"] == "e2e-local" {
			found = true
		}
	}
	if !found {
		t.Error("created fileshare not found in list")
	}

	// TEST — local share with a real temp dir should pass
	idInt := int(id.(float64))
	resp = doJSON(t, http.MethodPost, fmt.Sprintf("/api/fileshares/%d/test", idInt), nil)
	assertStatus(t, resp, http.StatusOK)

	// DELETE
	resp = doJSON(t, http.MethodDelete, fmt.Sprintf("/api/fileshares/%d", idInt), nil)
	assertStatus(t, resp, http.StatusNoContent)
	resp.Body.Close()

	// LIST — should no longer contain it
	resp = doJSON(t, http.MethodGet, "/api/fileshares", nil)
	assertStatus(t, resp, http.StatusOK)
	decodeJSON(t, resp, &list)
	for _, fs := range list {
		if fs["label"] == "e2e-local" {
			t.Error("deleted fileshare still in list")
		}
	}
}

// ─── Rules ───────────────────────────────────────────────────────────────────

func TestRules_CRUD(t *testing.T) {
	// CREATE
	resp := doJSON(t, http.MethodPost, "/api/rules", map[string]any{
		"label":              "e2e-rule",
		"gmail_query":        "has:attachment",
		"subfolder_template": "{year}/{month}",
		"enabled":            true,
	})
	assertStatus(t, resp, http.StatusOK)
	var created map[string]any
	decodeJSON(t, resp, &created)
	idInt := int(created["id"].(float64))

	// LIST
	resp = doJSON(t, http.MethodGet, "/api/rules", nil)
	assertStatus(t, resp, http.StatusOK)
	var list []map[string]any
	decodeJSON(t, resp, &list)
	found := false
	for _, r := range list {
		if r["label"] == "e2e-rule" {
			found = true
		}
	}
	if !found {
		t.Error("created rule not found in list")
	}

	// UPDATE
	resp = doJSON(t, http.MethodPut, fmt.Sprintf("/api/rules/%d", idInt), map[string]any{
		"label":              "e2e-rule-updated",
		"gmail_query":        "has:attachment",
		"subfolder_template": "{year}/{month}/{day}",
		"enabled":            false,
	})
	assertStatus(t, resp, http.StatusOK)
	var updated map[string]any
	decodeJSON(t, resp, &updated)
	if updated["label"] != "e2e-rule-updated" {
		t.Errorf("expected updated label, got %v", updated["label"])
	}

	// DELETE
	resp = doJSON(t, http.MethodDelete, fmt.Sprintf("/api/rules/%d", idInt), nil)
	assertStatus(t, resp, http.StatusNoContent)
	resp.Body.Close()
}

// ─── Accounts ────────────────────────────────────────────────────────────────

func TestAccounts_ListEmpty(t *testing.T) {
	resp := doJSON(t, http.MethodGet, "/api/accounts", nil)
	assertStatus(t, resp, http.StatusOK)
	var list []any
	decodeJSON(t, resp, &list)
	// Just verify we get a JSON array (may contain leftovers from other tests,
	// but it must not error).
	if list == nil {
		t.Error("expected JSON array, got nil")
	}
}

// ─── Settings ────────────────────────────────────────────────────────────────

func TestSettings_GetAndUpdate(t *testing.T) {
	// GET baseline
	resp := doJSON(t, http.MethodGet, "/api/settings", nil)
	assertStatus(t, resp, http.StatusOK)
	var settings map[string]string
	decodeJSON(t, resp, &settings)
	if settings == nil {
		t.Fatal("expected settings map")
	}

	// PUT — update scheduler interval
	resp = doJSON(t, http.MethodPut, "/api/settings", map[string]string{
		"scheduler_interval_minutes": "45",
	})
	assertStatus(t, resp, http.StatusOK)
	var updated map[string]string
	decodeJSON(t, resp, &updated)
	if updated["scheduler_interval_minutes"] != "45" {
		t.Errorf("expected 45, got %q", updated["scheduler_interval_minutes"])
	}

	// PUT — google_client_secret should be masked in response
	resp = doJSON(t, http.MethodPut, "/api/settings", map[string]string{
		"google_client_id":     "my-client-id",
		"google_client_secret": "super-secret",
	})
	assertStatus(t, resp, http.StatusOK)
	decodeJSON(t, resp, &updated)
	if updated["google_client_secret"] != "****" {
		t.Errorf("secret should be masked, got %q", updated["google_client_secret"])
	}
	if updated["google_client_id"] != "my-client-id" {
		t.Errorf("client_id not saved, got %q", updated["google_client_id"])
	}

	// PUT again with placeholder — must not overwrite stored secret
	resp = doJSON(t, http.MethodPut, "/api/settings", map[string]string{
		"google_client_secret": "****",
	})
	assertStatus(t, resp, http.StatusOK)
	decodeJSON(t, resp, &updated)
	if updated["google_client_secret"] != "****" {
		t.Errorf("expected masked secret, got %q", updated["google_client_secret"])
	}
}

// ─── Logs ────────────────────────────────────────────────────────────────────

func TestLogs_ListEmpty(t *testing.T) {
	resp := doJSON(t, http.MethodGet, "/api/logs", nil)
	assertStatus(t, resp, http.StatusOK)
	var body struct {
		Total int   `json:"total"`
		Page  int   `json:"page"`
		Items []any `json:"items"`
	}
	decodeJSON(t, resp, &body)
	if body.Page < 1 {
		t.Errorf("expected page >= 1, got %d", body.Page)
	}
}

// ─── Static / SPA ────────────────────────────────────────────────────────────

func TestStaticFiles_Served(t *testing.T) {
	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for /, got %d", resp.StatusCode)
	}
}
