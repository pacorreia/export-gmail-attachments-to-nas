package smb

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// SMB implements fileshare.FileShare for SMB shares.
type SMB struct {
	host     string
	share    string
	username string
	password string
	conn     net.Conn
	session  *smb2.Session
	fs       *smb2.Share
}

func New(host, share, username, password string) *SMB {
	return &SMB{host: host, share: share, username: username, password: password}
}

func (s *SMB) connect(ctx context.Context) error {
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
	fs, err := sess.Mount(s.share)
	if err != nil {
		sess.Logoff()
		conn.Close()
		return fmt.Errorf("mount %s: %w", s.share, err)
	}
	s.conn = conn
	s.session = sess
	s.fs = fs
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
