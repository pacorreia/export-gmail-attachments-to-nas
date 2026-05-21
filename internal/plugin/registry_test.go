package plugin

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// stubPlugin is a test double that records events dispatched to it.
type stubPlugin struct {
	name   string
	mu     sync.Mutex
	events []AttachmentEvent
	errOn  int // return error on the nth call (1-based); 0 = never
	calls  int
}

func (s *stubPlugin) Name() string { return s.name }

func (s *stubPlugin) OnAttachmentSaved(_ context.Context, e AttachmentEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.errOn > 0 && s.calls == s.errOn {
		return errors.New("stub error")
	}
	s.events = append(s.events, e)
	return nil
}

func (s *stubPlugin) received() []AttachmentEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AttachmentEvent(nil), s.events...)
}

func setup(t *testing.T) {
	t.Helper()
	Clear()
	t.Cleanup(Clear)
}

func TestRegisterAndDispatch(t *testing.T) {
	setup(t)

	p := &stubPlugin{name: "test"}
	Register(p)

	event := AttachmentEvent{Filename: "invoice.pdf"}
	Dispatch(context.Background(), event)

	got := p.received()
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Filename != "invoice.pdf" {
		t.Errorf("unexpected filename: %s", got[0].Filename)
	}
}

func TestDispatch_MultiplePlugins(t *testing.T) {
	setup(t)

	a := &stubPlugin{name: "a"}
	b := &stubPlugin{name: "b"}
	Register(a)
	Register(b)

	Dispatch(context.Background(), AttachmentEvent{Filename: "doc.pdf"})

	if len(a.received()) != 1 || len(b.received()) != 1 {
		t.Error("both plugins should receive the event")
	}
}

func TestDispatch_PluginErrorDoesNotAbort(t *testing.T) {
	setup(t)

	failing := &stubPlugin{name: "failing", errOn: 1}
	succeeding := &stubPlugin{name: "succeeding"}
	Register(failing)
	Register(succeeding)

	Dispatch(context.Background(), AttachmentEvent{Filename: "file.pdf"})

	// The second plugin must still receive the event even if the first failed.
	if len(succeeding.received()) != 1 {
		t.Error("succeeding plugin should still receive event after a failing plugin")
	}
}

func TestClear(t *testing.T) {
	setup(t)

	p := &stubPlugin{name: "p"}
	Register(p)
	Clear()
	Dispatch(context.Background(), AttachmentEvent{Filename: "x.pdf"})

	if len(p.received()) != 0 {
		t.Error("plugin should not receive events after Clear")
	}
}

func TestDispatch_NilRegistry(t *testing.T) {
	setup(t)
	// Should not panic when no plugins are registered.
	Dispatch(context.Background(), AttachmentEvent{})
}

func TestDispatch_Concurrent(t *testing.T) {
	setup(t)

	p := &stubPlugin{name: "concurrent"}
	Register(p)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Dispatch(context.Background(), AttachmentEvent{Filename: "f.pdf"})
		}()
	}
	wg.Wait()

	if len(p.received()) != 100 {
		t.Errorf("expected 100 events, got %d", len(p.received()))
	}
}
