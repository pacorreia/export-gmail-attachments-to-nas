package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
)

func clearSettings(t *testing.T) {
	t.Helper()
	db.DB.Exec("DELETE FROM settings")
}

func TestGetSettings_ReturnsJSON(t *testing.T) {
	clearSettings(t)
	t.Cleanup(func() { clearSettings(t) })

	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	rr := httptest.NewRecorder()
	GetSettings(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestUpdateSettings_SavesValue(t *testing.T) {
	clearSettings(t)
	t.Cleanup(func() { clearSettings(t) })

	payload := map[string]string{"scheduler_interval_minutes": "30"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	UpdateSettings(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["scheduler_interval_minutes"] != "30" {
		t.Errorf("expected '30', got %q", resp["scheduler_interval_minutes"])
	}
}

func TestUpdateSettings_RejectsReadonlyDatabaseURL(t *testing.T) {
	clearSettings(t)
	t.Cleanup(func() { clearSettings(t) })

	payload := map[string]string{"database_url": "postgres://evil"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	UpdateSettings(rr, req)

	// The DB URL must not be persisted.
	val := db.GetSetting("database_url", "")
	if val == "postgres://evil" {
		t.Error("database_url should be read-only and not saved")
	}
}

func TestUpdateSettings_EncryptsClientSecret(t *testing.T) {
	clearSettings(t)
	t.Cleanup(func() { clearSettings(t) })

	payload := map[string]string{"google_client_secret": "my-real-secret"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	UpdateSettings(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// The response must mask the secret.
	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["google_client_secret"] != "****" {
		t.Errorf("expected masked '****', got %q", resp["google_client_secret"])
	}

	// The stored value must differ from the plaintext (i.e. it was encrypted).
	stored := db.GetSetting("google_client_secret", "")
	if stored == "my-real-secret" {
		t.Error("secret was stored as plaintext, expected encrypted value")
	}
	if stored == "" {
		t.Error("secret was not stored at all")
	}
}

func TestUpdateSettings_SkipsPlaceholderSecret(t *testing.T) {
	clearSettings(t)
	t.Cleanup(func() { clearSettings(t) })

	// First, store a real secret.
	payload := map[string]string{"google_client_secret": "original-secret"}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	UpdateSettings(httptest.NewRecorder(), req)

	originalStored := db.GetSetting("google_client_secret", "")

	// Now send the placeholder — should NOT overwrite.
	payload2 := map[string]string{"google_client_secret": "****"}
	body2, _ := json.Marshal(payload2)
	req2 := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	UpdateSettings(httptest.NewRecorder(), req2)

	afterStored := db.GetSetting("google_client_secret", "")
	if afterStored != originalStored {
		t.Error("placeholder '****' should not overwrite the stored secret")
	}
}

func TestUpdateSettings_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader([]byte("{bad json")))
	rr := httptest.NewRecorder()
	UpdateSettings(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}
