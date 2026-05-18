package local

import (
	"context"
	"os"
	"path/filepath"
)

// Local implements fileshare.FileShare for the local filesystem.
type Local struct {
	base string
}

func New(base string) *Local {
	return &Local{base: base}
}

func (l *Local) Test(_ context.Context) error {
	return os.MkdirAll(l.base, 0755)
}

func (l *Local) Write(_ context.Context, relPath string, data []byte) error {
	full := filepath.Join(l.base, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		return err
	}
	return os.WriteFile(full, data, 0644)
}

func (l *Local) Close() error { return nil }
