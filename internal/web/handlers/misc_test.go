package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListLogs_Paginated(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/logs?page=1", nil)
	rr := httptest.NewRecorder()
	ListLogs(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
	var resp struct {
		Total int   `json:"total"`
		Page  int   `json:"page"`
		Items []any `json:"items"`
	}
	decodeResponse(t, rr, &resp)
	if resp.Page != 1 {
		t.Errorf("expected page 1, got %d", resp.Page)
	}
}

func TestListLogs_DefaultPage(t *testing.T) {
	// page=0 (missing) should default to 1
	req := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
	rr := httptest.NewRecorder()
	ListLogs(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
	var resp struct {
		Page int `json:"page"`
	}
	decodeResponse(t, rr, &resp)
	if resp.Page != 1 {
		t.Errorf("expected default page 1, got %d", resp.Page)
	}
}

func TestListAccounts(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/accounts", nil)
	rr := httptest.NewRecorder()
	ListAccounts(rr, req)

	assertStatusCode(t, rr, http.StatusOK)
}

func TestDeleteAccount_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/api/accounts/9999", nil)
	req = withURLParam(req, "id", "9999")
	rr := httptest.NewRecorder()
	DeleteAccount(rr, req)

	// Deleting a non-existent record with GORM returns 204 (no error, 0 rows affected).
	if rr.Code != http.StatusNoContent && rr.Code != http.StatusInternalServerError {
		t.Errorf("unexpected status: %d", rr.Code)
	}
}
