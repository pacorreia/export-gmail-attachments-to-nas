package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/plugin"
)

func TestOnAttachmentSaved_Success(t *testing.T) {
	var received plugin.AttachmentEvent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := New("test", Config{URL: srv.URL, Retries: 1})
	event := plugin.AttachmentEvent{Filename: "invoice.pdf", Subject: "Test"}

	if err := wh.OnAttachmentSaved(context.Background(), event); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if received.Filename != "invoice.pdf" {
		t.Errorf("filename mismatch: got %q", received.Filename)
	}
}

func TestOnAttachmentSaved_SignatureHeader(t *testing.T) {
	const secret = "my-webhook-secret"
	var gotSig string
	var body []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Signature-SHA256")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := New("sig-test", Config{URL: srv.URL, Secret: secret, Retries: 1})
	if err := wh.OnAttachmentSaved(context.Background(), plugin.AttachmentEvent{Filename: "f.pdf"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))

	if gotSig != want {
		t.Errorf("signature mismatch: got %q, want %q", gotSig, want)
	}
}

func TestOnAttachmentSaved_NoSignatureWhenSecretEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sig := r.Header.Get("X-Signature-SHA256"); sig != "" {
			t.Errorf("unexpected signature header: %s", sig)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := New("no-sig", Config{URL: srv.URL, Secret: "", Retries: 1})
	wh.OnAttachmentSaved(context.Background(), plugin.AttachmentEvent{})
}

func TestOnAttachmentSaved_RetriesOnServerError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := New("retry", Config{URL: srv.URL, Retries: 3})
	wh.client = &http.Client{Timeout: 5 * time.Second}

	if err := wh.OnAttachmentSaved(context.Background(), plugin.AttachmentEvent{}); err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls (2 failures + 1 success), got %d", calls)
	}
}

func TestOnAttachmentSaved_FailsAfterAllRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	wh := New("always-fail", Config{URL: srv.URL, Retries: 2})
	wh.client = &http.Client{Timeout: 5 * time.Second}

	err := wh.OnAttachmentSaved(context.Background(), plugin.AttachmentEvent{})
	if err == nil {
		t.Error("expected error when all retries fail")
	}
}

func TestOnAttachmentSaved_ContentTypeJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := New("ct", Config{URL: srv.URL, Retries: 1})
	wh.OnAttachmentSaved(context.Background(), plugin.AttachmentEvent{})
}
