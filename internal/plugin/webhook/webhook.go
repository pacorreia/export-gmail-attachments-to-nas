package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/plugin"
)

// Config holds webhook plugin configuration.
type Config struct {
	URL     string `json:"url"`
	Secret  string `json:"secret"`
	Retries int    `json:"retries"`
}

// Webhook is a plugin that POSTs events to an HTTP endpoint.
type Webhook struct {
	label  string
	config Config
	client *http.Client
}

// New creates a new Webhook plugin.
func New(label string, cfg Config) *Webhook {
	if cfg.Retries <= 0 {
		cfg.Retries = 3
	}
	return &Webhook{
		label:  label,
		config: cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *Webhook) Name() string { return "webhook:" + w.label }

func (w *Webhook) OnAttachmentSaved(ctx context.Context, event plugin.AttachmentEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	sig := ""
	if w.config.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.config.Secret))
		mac.Write(payload)
		sig = hex.EncodeToString(mac.Sum(nil))
	}

	var lastErr error
	for attempt := 0; attempt < w.config.Retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.config.URL, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("new request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if sig != "" {
			req.Header.Set("X-Signature-SHA256", sig)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	return lastErr
}
