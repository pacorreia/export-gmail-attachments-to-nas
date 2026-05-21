package subprocess

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/plugin"
)

// trueExe returns the path to a binary that always exits 0.
// On Linux/macOS, /bin/true or `true` (from PATH) works.
func trueExe(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("true"); err == nil {
		return p
	}
	t.Skip("'true' binary not found in PATH")
	return ""
}

// falseExe returns the path to a binary that always exits non-zero.
func falseExe(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("false"); err == nil {
		return p
	}
	t.Skip("'false' binary not found in PATH")
	return ""
}

func TestNew_DefaultTimeout(t *testing.T) {
	s := New("test", Config{Executable: "/bin/true"})
	if s.config.TimeoutSec != 30 {
		t.Errorf("expected default timeout 30, got %d", s.config.TimeoutSec)
	}
}

func TestNew_CustomTimeout(t *testing.T) {
	s := New("test", Config{Executable: "/bin/true", TimeoutSec: 5})
	if s.config.TimeoutSec != 5 {
		t.Errorf("expected timeout 5, got %d", s.config.TimeoutSec)
	}
}

func TestName(t *testing.T) {
	s := New("my-script", Config{})
	if got := s.Name(); got != "subprocess:my-script" {
		t.Errorf("unexpected name: %q", got)
	}
}

func TestOnAttachmentSaved_Success(t *testing.T) {
	exe := trueExe(t)
	s := New("ok", Config{Executable: exe, TimeoutSec: 5})

	err := s.OnAttachmentSaved(context.Background(), plugin.AttachmentEvent{
		Filename: "test.pdf",
		Subject:  "Test",
	})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

func TestOnAttachmentSaved_NonZeroExit(t *testing.T) {
	exe := falseExe(t)
	s := New("fail", Config{Executable: exe, TimeoutSec: 5})

	err := s.OnAttachmentSaved(context.Background(), plugin.AttachmentEvent{})
	if err == nil {
		t.Error("expected error for non-zero exit code")
	}
}

func TestOnAttachmentSaved_NotFound(t *testing.T) {
	s := New("missing", Config{Executable: "/nonexistent/binary", TimeoutSec: 5})
	err := s.OnAttachmentSaved(context.Background(), plugin.AttachmentEvent{})
	if err == nil {
		t.Error("expected error for missing executable")
	}
}

func TestOnAttachmentSaved_ContextCancelled(t *testing.T) {
	// Use a real long-running process and cancel the context immediately.
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not found in PATH")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := New("sleep", Config{Executable: "sleep", Args: []string{"10"}, TimeoutSec: 30})
	err := s.OnAttachmentSaved(ctx, plugin.AttachmentEvent{})
	if err == nil {
		t.Error("expected error when context is cancelled")
	}
}

func TestOnAttachmentSaved_WithArgs(t *testing.T) {
	// Use 'cat' to echo stdin back — just verify it exits 0 with args.
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("cat not found in PATH")
	}

	s := New("cat", Config{Executable: cat, TimeoutSec: 5})
	err = s.OnAttachmentSaved(context.Background(), plugin.AttachmentEvent{Filename: "f.pdf"})
	if err != nil {
		t.Fatalf("expected success: %v", err)
	}
}

func TestOnAttachmentSaved_TimeoutExpires(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not found in PATH")
	}
	if os.Getenv("CI") != "" {
		t.Skip("skipping slow timeout test in CI")
	}

	s := New("timeout", Config{Executable: "sleep", Args: []string{"10"}, TimeoutSec: 1})
	start := time.Now()
	err := s.OnAttachmentSaved(context.Background(), plugin.AttachmentEvent{})
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected error due to timeout")
	}
	if elapsed > 5*time.Second {
		t.Errorf("timeout did not fire in time: elapsed %v", elapsed)
	}
}
