package smb

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// smbFS abstracts the methods of *smb2.Share used by this package.
type smbFS interface {
	ReadDir(name string) ([]os.FileInfo, error)
	MkdirAll(path string, perm os.FileMode) error
	Create(name string) (io.ReadWriteCloser, error)
	Umount() error
}

// smbSess abstracts the methods of *smb2.Session used by this package.
type smbSess interface {
	Logoff() error
}

// realSMBShare wraps *smb2.Share to satisfy smbFS (adapts Create's return type).
type realSMBShare struct{ s *smb2.Share }

func (r *realSMBShare) ReadDir(name string) ([]os.FileInfo, error)     { return r.s.ReadDir(name) }
func (r *realSMBShare) MkdirAll(path string, perm os.FileMode) error   { return r.s.MkdirAll(path, perm) }
func (r *realSMBShare) Create(name string) (io.ReadWriteCloser, error) { return r.s.Create(name) }
func (r *realSMBShare) Umount() error                                   { return r.s.Umount() }

// SMB implements fileshare.FileShare for SMB shares.
type SMB struct {
	host     string
	share    string
	username string
	password string
	conn     io.Closer
	session  smbSess
	fs       smbFS
	// dialFn is injected for tests; nil means use the real SMB2 dialer.
	dialFn func(ctx context.Context) (io.Closer, smbSess, smbFS, error)
}

func New(host, share, username, password string) *SMB {
	return &SMB{host: host, share: share, username: username, password: password}
}

// withDialer replaces the connection function — used in tests.
func (s *SMB) withDialer(fn func(ctx context.Context) (io.Closer, smbSess, smbFS, error)) *SMB {
	s.dialFn = fn
	return s
}

func (s *SMB) connect(ctx context.Context) error {
	if s.dialFn != nil {
		conn, sess, fs, err := s.dialFn(ctx)
		if err != nil {
			return err
		}
		s.conn, s.session, s.fs = conn, sess, fs
		return nil
	}
	// real SMB2 implementation
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", s.host+":445")
	if err != nil {
		return fmt.Errorf("dial %s:445: %w", s.host, err)
	}
	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     s.username,
			Password: s.password,
		},
	}
	sess, err := dialer.DialContext(ctx, conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smb dial: %w", err)
	}
	rawFS, err := sess.Mount(s.share)
	if err != nil {
		sess.Logoff()
		conn.Close()
		return fmt.Errorf("mount %s: %w", s.share, err)
	}
	s.conn = conn
	s.session = sess
	s.fs = &realSMBShare{s: rawFS}
	return nil
}

func (s *SMB) Test(ctx context.Context) error {
	if err := s.connect(ctx); err != nil {
		return err
	}
	defer s.Close()
	_, err := s.fs.ReadDir(".")
	return err
}

func (s *SMB) Write(ctx context.Context, relPath string, data []byte) error {
	if s.fs == nil {
		if err := s.connect(ctx); err != nil {
			return err
		}
	}
	dir := filepath.Dir(relPath)
	parts := strings.Split(filepath.ToSlash(dir), "/")
	cur := ""
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		cur = cur + "\\" + p

		_ = s.fs.MkdirAll(strings.TrimPrefix(cur, "\\"), 0755)
	}
	f, err := s.fs.Create(filepath.ToSlash(relPath))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func (s *SMB) Close() error {
	if s.fs != nil {
		s.fs.Umount()
		s.fs = nil
	}
	if s.session != nil {
		s.session.Logoff()
		s.session = nil
	}
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	return nil
}
