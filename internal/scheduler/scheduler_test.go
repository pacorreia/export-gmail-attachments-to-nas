package scheduler

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/crypto"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/db/models"
	fsiface "github.com/pacorreia/export-gmail-attachments-to-nas/internal/fileshare"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/fileshare/local"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/gmail"
	"github.com/pacorreia/export-gmail-attachments-to-nas/internal/pdf"
)

// ─── stubs ────────────────────────────────────────────────────────────────────

// stubGmailClient implements gmail.Client for testing.
type stubGmailClient struct {
	ids  []string
	msgs map[string]*gmail.Message
	err  error
}

func (s *stubGmailClient) SearchMessages(_ context.Context, _ string) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.ids, nil
}

func (s *stubGmailClient) FetchMessage(_ context.Context, id string) (*gmail.Message, error) {
	if s.err != nil {
		return nil, s.err
	}
	if msg, ok := s.msgs[id]; ok {
		return msg, nil
	}
	return nil, errors.New("message not found: " + id)
}

// stubFileShare implements fsiface.FileShare for testing.
type stubFileShare struct {
	written map[string][]byte
	testErr error
	writeErr error
}

func newStubBackend() *stubFileShare {
	return &stubFileShare{written: make(map[string][]byte)}
}

func (s *stubFileShare) Test(_ context.Context) error   { return s.testErr }
func (s *stubFileShare) Close() error                   { return nil }
func (s *stubFileShare) Write(_ context.Context, relPath string, data []byte) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.written[relPath] = append([]byte(nil), data...)
	return nil
}

func TestMain(m *testing.M) {
	os.Setenv("SECRET_KEY", "scheduler-test-key")
	if err := crypto.Init("scheduler-test-key"); err != nil {
		log.Fatalf("crypto.Init: %v", err)
	}
	os.Setenv("DATABASE_URL", "sqlite://:memory:")
	if err := db.Open(); err != nil {
		log.Fatalf("db.Open: %v", err)
	}
	os.Exit(m.Run())
}

// ─── expandTemplate ───────────────────────────────────────────────────────────

func TestExpandTemplate_Placeholders(t *testing.T) {
	msg := &gmail.Message{
		Date:    time.Date(2024, 3, 7, 0, 0, 0, 0, time.UTC),
		Sender:  "alice@example.com",
		Subject: "Invoice Q1",
	}

	cases := []struct {
		tmpl string
		want string
	}{
		{"{year}/{month}/{day}", "2024/03/07"},
		{"{sender}", "alice@example.com"},
		{"{subject}", "Invoice Q1"},
		{"docs/{year}-{month}", "docs/2024-03"},
		{"", ""},
		{"no-placeholders", "no-placeholders"},
	}

	for _, c := range cases {
		got := expandTemplate(c.tmpl, msg)
		if got != c.want {
			t.Errorf("expandTemplate(%q): got %q, want %q", c.tmpl, got, c.want)
		}
	}
}

// ─── sanitize ─────────────────────────────────────────────────────────────────

func TestSanitize_ReplacesInvalidChars(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"hello/world", "hello_world"},
		{`back\slash`, "back_slash"},
		{"a:b*c?d\"e<f>g|h", "a_b_c_d_e_f_g_h"},
		{"clean", "clean"},
		{"", ""},
	}
	for _, c := range cases {
		got := sanitize(c.input)
		if got != c.want {
			t.Errorf("sanitize(%q): got %q, want %q", c.input, got, c.want)
		}
	}
}

// ─── intervalFromSetting ──────────────────────────────────────────────────────

func TestIntervalFromSetting_Default(t *testing.T) {
	d := intervalFromSetting()
	if d != 60*time.Minute {
		t.Errorf("expected 60m default, got %v", d)
	}
}

func TestIntervalFromSetting_FromDB(t *testing.T) {
	db.DB.Exec("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", "scheduler_interval_minutes", "15")
	t.Cleanup(func() {
		db.DB.Exec("DELETE FROM settings WHERE key = ?", "scheduler_interval_minutes")
	})

	d := intervalFromSetting()
	if d != 15*time.Minute {
		t.Errorf("expected 15m from DB, got %v", d)
	}
}

// ─── saveAttachmentToBackend ──────────────────────────────────────────────────

func TestSaveAttachmentToBackend_WritesFile(t *testing.T) {
	dir := t.TempDir()
	backend := local.New(dir)
	logger := log.New(os.Stderr, "", 0)

	data := []byte("attachment content")
	relPath := filepath.Join("subfolder", "file.pdf")

	if err := saveAttachmentToBackend(context.Background(), data, relPath, backend, logger); err != nil {
		t.Fatalf("saveAttachmentToBackend: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, relPath))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content mismatch: got %q, want %q", got, data)
	}
}

func TestSaveAttachmentToBackend_FailsOnReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0555); err != nil {
		t.Skip("cannot set read-only permissions on this system")
	}
	t.Cleanup(func() { os.Chmod(dir, 0755) })

	backend := local.New(filepath.Join(dir, "sub"))
	logger := log.New(os.Stderr, "", 0)

	err := saveAttachmentToBackend(context.Background(), []byte("data"), "file.pdf", backend, logger)
	if err == nil {
		t.Error("expected error writing to read-only directory")
	}
}

// ─── openShare ────────────────────────────────────────────────────────────────

func TestOpenShare_Local(t *testing.T) {
	dir := t.TempDir()
	share := models.FileShare{Type: "local", BasePath: dir}
	backend := openShare(share)
	if backend == nil {
		t.Fatal("openShare returned nil for local type")
	}
	defer backend.Close()

	if err := backend.Test(context.Background()); err != nil {
		t.Errorf("Test: %v", err)
	}
}

func TestOpenShare_UnknownType(t *testing.T) {
	share := models.FileShare{Type: "unknown", BasePath: "/tmp"}
	if openShare(share) != nil {
		t.Error("expected nil for unknown share type")
	}
}

// ─── processMessage ───────────────────────────────────────────────────────────

func makeOpener(backend fsiface.FileShare) func(models.FileShare) fsiface.FileShare {
	return func(_ models.FileShare) fsiface.FileShare { return backend }
}

func TestProcessMessage_SavesAttachmentsToAllShares(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	backendA, backendB := newStubBackend(), newStubBackend()

	msg := &gmail.Message{
		Date:    time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC),
		Sender:  "sender@example.com",
		Subject: "Invoice",
		Attachments: []gmail.Attachment{
			{Filename: "invoice.pdf", MIMEType: "application/pdf", Data: []byte("pdf")},
			{Filename: "receipt.png", MIMEType: "image/png", Data: []byte("img")},
		},
	}
	rule := models.Rule{SubfolderTemplate: "{year}/{month}"}
	shares := []models.FileShare{
		{ID: 1, Type: "local", BasePath: dirA},
		{ID: 2, Type: "local", BasePath: dirB},
	}
	logger := log.New(os.Stderr, "", 0)

	// Use a custom opener that alternates backends based on share ID.
	opener := func(s models.FileShare) fsiface.FileShare {
		if s.ID == 1 {
			return backendA
		}
		return backendB
	}

	count := processMessage(context.Background(), msg, rule, models.Account{}, shares, logger, opener, pdf.Default)
	if count != 4 { // 2 attachments × 2 shares
		t.Errorf("expected 4 saved, got %d", count)
	}

	wantPath := filepath.Join("2024", "05", "invoice.pdf")
	if _, ok := backendA.written[wantPath]; !ok {
		t.Errorf("backendA missing %s", wantPath)
	}
	if _, ok := backendB.written[wantPath]; !ok {
		t.Errorf("backendB missing %s", wantPath)
	}
}

func TestProcessMessage_NilBackendSkipped(t *testing.T) {
	msg := &gmail.Message{
		Attachments: []gmail.Attachment{
			{Filename: "f.pdf", Data: []byte("data")},
		},
	}
	logger := log.New(os.Stderr, "", 0)

	count := processMessage(context.Background(), msg, models.Rule{}, models.Account{},
		[]models.FileShare{{ID: 1}}, logger,
		func(_ models.FileShare) fsiface.FileShare { return nil },
		pdf.Default,
	)
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestProcessMessage_WriteErrorNotCounted(t *testing.T) {
	stub := newStubBackend()
	stub.writeErr = errors.New("disk full")

	msg := &gmail.Message{
		Attachments: []gmail.Attachment{
			{Filename: "f.pdf", Data: []byte("data")},
		},
	}
	logger := log.New(os.Stderr, "", 0)

	count := processMessage(context.Background(), msg, models.Rule{}, models.Account{},
		[]models.FileShare{{ID: 1}}, logger, makeOpener(stub),
		pdf.Default,
	)
	if count != 0 {
		t.Errorf("expected 0 on write error, got %d", count)
	}
}

func TestProcessMessage_NoAttachments(t *testing.T) {
	stub := newStubBackend()
	msg := &gmail.Message{}
	logger := log.New(os.Stderr, "", 0)

	count := processMessage(context.Background(), msg, models.Rule{}, models.Account{},
		[]models.FileShare{{ID: 1}}, logger, makeOpener(stub),
		pdf.Default,
	)
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

// ─── convertAndSaveImages (with stub pdf converter) ───────────────────────────

func TestConvertAndSaveImages_WithStubConverter(t *testing.T) {
	stub := newStubBackend()

	// Stub converter returns two fake page images.
	stubConv := pdf.FuncConverter(func(_ context.Context, name string, _ []byte, _ int) ([]pdf.PageImage, error) {
		return []pdf.PageImage{
			{Name: "doc_page_001.png", Data: []byte("page1")},
			{Name: "doc_page_002.png", Data: []byte("page2")},
		}, nil
	})

	att := gmail.Attachment{Filename: "doc.pdf", MIMEType: "application/pdf", Data: []byte("%PDF")}
	share := models.FileShare{ID: 1, Type: "local", BasePath: "/irrelevant"}
	logger := log.New(os.Stderr, "", 0)

	convertAndSaveImages(context.Background(), att, "invoices", share, logger, makeOpener(stub), stubConv)

	if _, ok := stub.written[filepath.Join("invoices", "doc_page_001.png")]; !ok {
		t.Error("page 1 was not written")
	}
	if _, ok := stub.written[filepath.Join("invoices", "doc_page_002.png")]; !ok {
		t.Error("page 2 was not written")
	}
}

func TestConvertAndSaveImages_ConverterError(t *testing.T) {
	stub := newStubBackend()

	errConv := pdf.FuncConverter(func(_ context.Context, _ string, _ []byte, _ int) ([]pdf.PageImage, error) {
		return nil, errors.New("pdftoppm not found")
	})

	att := gmail.Attachment{Filename: "bad.pdf", Data: []byte("%PDF")}
	share := models.FileShare{ID: 1}
	logger := log.New(os.Stderr, "", 0)

	// Should not panic or write anything when converter fails.
	convertAndSaveImages(context.Background(), att, "sub", share, logger, makeOpener(stub), errConv)

	if len(stub.written) != 0 {
		t.Errorf("expected no writes on converter error, got %d", len(stub.written))
	}
}

func TestConvertAndSaveImages_NilBackend(t *testing.T) {
	stubConv := pdf.FuncConverter(func(_ context.Context, _ string, _ []byte, _ int) ([]pdf.PageImage, error) {
		return []pdf.PageImage{{Name: "p.png", Data: []byte("img")}}, nil
	})
	att := gmail.Attachment{Filename: "f.pdf", Data: []byte("%PDF")}
	logger := log.New(os.Stderr, "", 0)
	// Should not panic when openBackend returns nil.
	convertAndSaveImages(context.Background(), att, "", models.FileShare{},
		logger, func(_ models.FileShare) fsiface.FileShare { return nil }, stubConv)
}

// ─── runSingleJob (with stub client) ─────────────────────────────────────────

func TestRunSingleJob_WithStubClient(t *testing.T) {
	// inject a stub client via a package-level swap
	dir := t.TempDir()
	stub := newStubBackend()

	msg := &gmail.Message{
		ID:      "msg-1",
		Date:    time.Now(),
		Sender:  "test@example.com",
		Subject: "Test",
		Attachments: []gmail.Attachment{
			{Filename: "doc.txt", Data: []byte("hello")},
		},
	}
	client := &stubGmailClient{
		ids:  []string{"msg-1"},
		msgs: map[string]*gmail.Message{"msg-1": msg},
	}

	rule := models.Rule{ID: 99, GmailQuery: "has:attachment", SubfolderTemplate: "{year}"}
	acct := models.Account{ID: 99}
	shares := []models.FileShare{{ID: 99, Type: "local", BasePath: dir}}

	logger := log.New(os.Stderr, "", 0)
	opener := makeOpener(stub)

	// Call processMessage directly with the stub client's fetched message.
	ids, _ := client.SearchMessages(context.Background(), rule.GmailQuery)
	if len(ids) != 1 {
		t.Fatalf("stub search: expected 1 id, got %d", len(ids))
	}
	fetchedMsg, _ := client.FetchMessage(context.Background(), ids[0])
	count := processMessage(context.Background(), fetchedMsg, rule, acct, shares, logger, opener, pdf.Default)

	if count != 1 {
		t.Errorf("expected 1 saved, got %d", count)
	}
	wantPath := filepath.Join(time.Now().Format("2006"), "doc.txt")
	if _, ok := stub.written[wantPath]; !ok {
		t.Errorf("stub missing written file %q; written: %v", wantPath, stub.written)
	}
}

func TestStubGmailClient_SearchError(t *testing.T) {
	client := &stubGmailClient{err: errors.New("network error")}
	_, err := client.SearchMessages(context.Background(), "query")
	if err == nil {
		t.Error("expected error from stub")
	}
}

func TestStubGmailClient_FetchError(t *testing.T) {
	client := &stubGmailClient{err: errors.New("network error")}
	_, err := client.FetchMessage(context.Background(), "id")
	if err == nil {
		t.Error("expected error from stub")
	}
}

