package models

import (
	"time"

	"gorm.io/gorm"
)

type Account struct {
	ID         uint           `gorm:"primarykey" json:"id"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
	Label      string         `json:"label"`
	Email      string         `json:"email"`
	TokenJSON  string         `json:"-"`
	LastSyncAt *time.Time     `json:"last_sync_at"`
}

type FileShare struct {
	ID          uint           `gorm:"primarykey" json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	Label       string         `json:"label"`
	Type        string         `json:"type"`
	Host        string         `json:"host"`
	Share       string         `json:"share"`
	Username    string         `json:"username"`
	PasswordEnc string         `json:"-"`
	BasePath    string         `json:"base_path"`
	LastTestAt  *time.Time     `json:"last_test_at"`
	LastTestOK  bool           `json:"last_test_ok"`
}

type Rule struct {
	ID                uint           `gorm:"primarykey" json:"id"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	DeletedAt         gorm.DeletedAt `gorm:"index" json:"-"`
	Label             string         `json:"label"`
	GmailQuery        string         `json:"gmail_query"`
	SubfolderTemplate string         `json:"subfolder_template"`
	ConvertPDFToImage bool           `json:"convert_pdf_to_image"`
	Enabled           bool           `json:"enabled"`
	// Schedule is either a Go duration string (e.g. "30m", "1h", "24h") or a JSON
	// recurrence object starting with '{'. Empty falls back to global setting.
	Schedule          string `json:"schedule"`
	DeleteAfterExport bool   `json:"delete_after_export"`
}

type RuleAssignment struct {
	RuleID      uint `gorm:"primarykey"`
	AccountID   uint `gorm:"primarykey"`
	FileShareID uint `gorm:"primarykey"`
}

type PluginConfig struct {
	ID         uint           `gorm:"primarykey" json:"id"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
	Type       string         `json:"type"`
	Label      string         `json:"label"`
	ConfigJSON string         `json:"config_json"`
	Enabled    bool           `json:"enabled"`
}

type RunLog struct {
	ID           uint       `gorm:"primarykey" json:"id"`
	CreatedAt    time.Time  `json:"created_at"`
	RuleID       uint       `json:"rule_id"`
	AccountID    uint       `json:"account_id"`
	FileShareID  uint       `json:"file_share_id"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at"`
	Status       string     `json:"status"`
	MessageCount int        `json:"message_count"`
	Error        string     `json:"error"`
}

type Setting struct {
	ID    uint   `gorm:"primarykey" json:"id"`
	Key   string `gorm:"uniqueIndex" json:"key"`
	Value string `json:"value"`
}

// SyncCheckpoint records the last successful sync time per (rule, account) pair.
// It is used to restrict the Gmail query to only new messages (after the checkpoint).
type SyncCheckpoint struct {
	RuleID    uint      `gorm:"primarykey" json:"rule_id"`
	AccountID uint      `gorm:"primarykey" json:"account_id"`
	SyncedAt  time.Time `json:"synced_at"`
}
