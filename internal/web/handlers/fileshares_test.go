package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db/models"
)

func clearFileShares(t *testing.T) {
	t.Helper()
	db.DB.Exec("DELETE FROM file_shares")
}

func withURLParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestListFileShares_Empty(t *testing.T) {
	clearFileShares(t)
	t.Cleanup(func() { clearFileShares(t) })

	req := httptest.NewRequest(http.MethodGet, "/api/fileshares", nil)
	rr := httptest.NewRecorder()
	ListFileShares(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
	var list []models.FileShare
	decodeResponse(t, rr, &list)
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}
}

func TestCreateFileShare_Local(t *testing.T) {
	clearFileShares(t)
	t.Cleanup(func() { clearFileShares(t) })

	dir := t.TempDir()
	body, _ := json.Marshal(map[string]any{
		"label":     "test-local",
		"type":      "local",
		"base_path": dir,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/fileshares", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	CreateFileShare(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
	var fs models.FileShare
	decodeResponse(t, rr, &fs)
	if fs.Label != "test-local" {
		t.Errorf("label mismatch: %q", fs.Label)
	}
	if fs.ID == 0 {
		t.Error("expected non-zero ID")
	}
}

func TestCreateFileShare_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/fileshares", bytes.NewReader([]byte("{bad")))
	rr := httptest.NewRecorder()
	CreateFileShare(rr, req)
	assertStatusCode(t, rr, http.StatusBadRequest)
}

func TestDeleteFileShare(t *testing.T) {
	clearFileShares(t)
	t.Cleanup(func() { clearFileShares(t) })

	// Create one first.
	fs := models.FileShare{Label: "to-delete", Type: "local", BasePath: t.TempDir()}
	db.DB.Create(&fs)

	req := httptest.NewRequest(http.MethodDelete, "/api/fileshares/"+fmt.Sprint(fs.ID), nil)
	req = withURLParam(req, "id", fmt.Sprint(fs.ID))
	rr := httptest.NewRecorder()
	DeleteFileShare(rr, req)

	assertStatusCode(t, rr, http.StatusNoContent)

	// Confirm it's gone.
	var count int64
	db.DB.Model(&models.FileShare{}).Where("id = ?", fs.ID).Count(&count)
	if count != 0 {
		t.Error("file share should have been deleted")
	}
}

func TestTestFileShare_Local(t *testing.T) {
	clearFileShares(t)
	t.Cleanup(func() { clearFileShares(t) })

	fs := models.FileShare{Label: "testable", Type: "local", BasePath: t.TempDir()}
	db.DB.Create(&fs)

	req := httptest.NewRequest(http.MethodPost, "/api/fileshares/"+fmt.Sprint(fs.ID)+"/test", nil)
	req = withURLParam(req, "id", fmt.Sprint(fs.ID))
	rr := httptest.NewRecorder()
	TestFileShare(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
	var resp map[string]any
	decodeResponse(t, rr, &resp)
	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp)
	}
}

func TestTestFileShare_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/fileshares/9999/test", nil)
	req = withURLParam(req, "id", "9999")
	rr := httptest.NewRecorder()
	TestFileShare(rr, req)
	assertStatusCode(t, rr, http.StatusNotFound)
}

func TestTestFileShare_UnknownType(t *testing.T) {
	clearFileShares(t)
	t.Cleanup(func() { clearFileShares(t) })

	fs := models.FileShare{Label: "bad", Type: "ftp", BasePath: "/tmp"}
	db.DB.Create(&fs)

	req := httptest.NewRequest(http.MethodPost, "/api/fileshares/"+fmt.Sprint(fs.ID)+"/test", nil)
	req = withURLParam(req, "id", fmt.Sprint(fs.ID))
	rr := httptest.NewRecorder()
	TestFileShare(rr, req)
	assertStatusCode(t, rr, http.StatusBadRequest)
}

// helpers shared across handler test files

func assertStatusCode(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		body, _ := io.ReadAll(rr.Body)
		t.Fatalf("expected HTTP %d, got %d — body: %s", want, rr.Code, body)
	}
}

func decodeResponse(t *testing.T, rr *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.NewDecoder(rr.Body).Decode(dst); err != nil {
		t.Fatalf("decode response JSON: %v", err)
	}
}
