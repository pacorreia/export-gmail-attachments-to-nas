package smb

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

// ─── stubs ────────────────────────────────────────────────────────────────────

type stubSMBFS struct {
	files     map[string]*bytes.Buffer
	mkdirs    []string
	readErr   error
	mkErr     error
	createErr error
	umounted  bool
}

func newStubFS() *stubSMBFS {
	return &stubSMBFS{files: make(map[string]*bytes.Buffer)}
}

func (s *stubSMBFS) ReadDir(_ string) ([]os.FileInfo, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	return nil, nil
}

func (s *stubSMBFS) MkdirAll(path string, _ os.FileMode) error {
	if s.mkErr != nil {
		return s.mkErr
	}
	s.mkdirs = append(s.mkdirs, path)
	return nil
}

func (s *stubSMBFS) Create(name string) (io.ReadWriteCloser, error) {
	if s.createErr != nil {
		return nil, s.createErr
	}
	buf := &bytes.Buffer{}
	s.files[name] = buf
	return nopRWC{buf}, nil
}

func (s *stubSMBFS) Umount() error {
	s.umounted = true
	return nil
}

// nopRWC wraps a bytes.Buffer as an io.ReadWriteCloser.
type nopRWC struct{ io.ReadWriter }

func (nopRWC) Close() error { return nil }

type stubSess struct{ loggedOff bool }

func (s *stubSess) Logoff() error { s.loggedOff = true; return nil }

type trackConn struct{ closed bool }

func (c *trackConn) Close() error { c.closed = true; return nil }

// makeDialer returns a dialFn that injects stub sess + fs.
func makeDialer(sess smbSess, fs smbFS, dialErr error) func(ctx context.Context) (io.Closer, smbSess, smbFS, error) {
	return func(ctx context.Context) (io.Closer, smbSess, smbFS, error) {
		if dialErr != nil {
			return nil, nil, nil, dialErr
		}
		return &trackConn{}, sess, fs, nil
	}
}

// ─── tests ────────────────────────────────────────────────────────────────────

func TestTest_Success(t *testing.T) {
	s := New("host", "share", "user", "pass")
	s.withDialer(makeDialer(&stubSess{}, newStubFS(), nil))
	if err := s.Test(context.Background()); err != nil {
		t.Fatalf("Test() unexpected error: %v", err)
	}
}

func TestTest_DialError(t *testing.T) {
	dialErr := errors.New("connection refused")
	s := New("host", "share", "user", "pass")
	s.withDialer(makeDialer(nil, nil, dialErr))
	err := s.Test(context.Background())
	if !errors.Is(err, dialErr) {
		t.Fatalf("Test() expected dial error, got: %v", err)
	}
}

func TestTest_ReadDirError(t *testing.T) {
	fs := newStubFS()
	fs.readErr = errors.New("permission denied")
	s := New("host", "share", "user", "pass")
	s.withDialer(makeDialer(&stubSess{}, fs, nil))
	if err := s.Test(context.Background()); err == nil {
		t.Error("Test() expected ReadDir error")
	}
}

func TestWrite_Success(t *testing.T) {
	fs := newStubFS()
	s := New("host", "share", "user", "pass")
	s.withDialer(makeDialer(&stubSess{}, fs, nil))

	data := []byte("hello world")
	if err := s.Write(context.Background(), "sub/file.txt", data); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	if got, ok := fs.files["sub/file.txt"]; !ok || !bytes.Equal(got.Bytes(), data) {
		t.Error("Write() file content mismatch")
	}
}

func TestWrite_CreateError(t *testing.T) {
	fs := newStubFS()
	fs.createErr = errors.New("access denied")
	s := New("host", "share", "user", "pass")
	s.withDialer(makeDialer(&stubSess{}, fs, nil))
	if err := s.Write(context.Background(), "file.txt", []byte("data")); err == nil {
		t.Error("Write() expected error on Create failure")
	}
}

func TestWrite_NestedPath(t *testing.T) {
	fs := newStubFS()
	s := New("host", "share", "user", "pass")
	s.withDialer(makeDialer(&stubSess{}, fs, nil))

	if err := s.Write(context.Background(), "a/b/c/file.pdf", []byte("pdf")); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}
	if len(fs.mkdirs) == 0 {
		t.Error("Write() expected MkdirAll calls for nested path")
	}
}

func TestClose_CleansUp(t *testing.T) {
	sess := &stubSess{}
	conn := &trackConn{}
	fs := newStubFS()
	s := New("host", "share", "user", "pass")
	s.withDialer(makeDialer(sess, fs, nil))
	_ = s.connect(context.Background())
	s.conn = conn // override to track Close

	_ = s.Close()

	if !sess.loggedOff {
		t.Error("Close() did not call session.Logoff()")
	}
	if !conn.closed {
		t.Error("Close() did not close the connection")
	}
	if !fs.umounted {
		t.Error("Close() did not call fs.Umount()")
	}
	if s.fs != nil || s.session != nil || s.conn != nil {
		t.Error("Close() did not nil out fields")
	}
}

func TestClose_IdempotentWhenNotConnected(t *testing.T) {
	s := New("host", "share", "user", "pass")
	if err := s.Close(); err != nil {
		t.Fatalf("Close() on unconnected SMB returned error: %v", err)
	}
}
