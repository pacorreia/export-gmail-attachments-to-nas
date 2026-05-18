package subprocess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/plugin"
)

// Config holds subprocess plugin configuration.
type Config struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
	TimeoutSec int      `json:"timeout_sec"`
}

// Subprocess is a plugin that invokes an external process.
type Subprocess struct {
	label  string
	config Config
}

// New creates a new Subprocess plugin.
func New(label string, cfg Config) *Subprocess {
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 30
	}
	return &Subprocess{label: label, config: cfg}
}

func (s *Subprocess) Name() string { return "subprocess:" + s.label }

func (s *Subprocess) OnAttachmentSaved(ctx context.Context, event plugin.AttachmentEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	timeout := time.Duration(s.config.TimeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.config.Executable, s.config.Args...)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("subprocess %s: %w\nstderr: %s", s.config.Executable, err, stderr.String())
	}
	return nil
}
