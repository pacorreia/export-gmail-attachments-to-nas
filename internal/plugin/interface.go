package plugin

import (
	"context"
	"time"
)

// AttachmentEvent carries metadata about a saved attachment.
type AttachmentEvent struct {
	RuleID      int64     `json:"rule_id"`
	AccountID   int64     `json:"account_id"`
	FileShareID int64     `json:"file_share_id"`
	Filename    string    `json:"filename"`
	NASPath     string    `json:"nas_path"`
	SizeBytes   int64     `json:"size_bytes"`
	EmailDate   time.Time `json:"email_date"`
	Subject     string    `json:"subject"`
	Sender      string    `json:"sender"`
	MIMEType    string    `json:"mime_type"`
}

// Plugin is the interface all plugins must implement.
type Plugin interface {
	Name() string
	OnAttachmentSaved(ctx context.Context, event AttachmentEvent) error
}
