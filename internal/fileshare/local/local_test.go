package local

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTest_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "new", "nested")
	l := New(subdir)

	if err := l.Test(context.Background()); err != nil {
		t.Fatalf("Test: %v", err)
	}
	if _, err := os.Stat(subdir); err != nil {
		t.Errorf("directory not created: %v", err)
	}
}

func TestWrite_CreatesFileAndDirectories(t *testing.T) {
	dir := t.TempDir()
	l := New(dir)

	data := []byte("hello, world")
	relPath := filepath.Join("sub", "dir", "file.txt")

	if err := l.Write(context.Background(), relPath, data); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, relPath))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("file content mismatch: got %q, want %q", got, data)
	}
}

func TestWrite_OverwritesExistingFile(t *testing.T) {
	dir := t.TempDir()
	l := New(dir)

	if err := l.Write(context.Background(), "file.txt", []byte("first")); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := l.Write(context.Background(), "file.txt", []byte("second")); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	got, _ := os.ReadFile(filepath.Join(dir, "file.txt"))
	if string(got) != "second" {
		t.Errorf("overwrite failed: got %q", got)
	}
}

func TestClose_IsNoOp(t *testing.T) {
	l := New(t.TempDir())
	if err := l.Close(); err != nil {
		t.Errorf("Close returned unexpected error: %v", err)
	}
}
