package plugin

import (
	"context"
	"log"
	"sync"
)

var (
	mu      sync.RWMutex
	plugins []Plugin
)

// Register adds a plugin to the registry.
func Register(p Plugin) {
	mu.Lock()
	defer mu.Unlock()
	plugins = append(plugins, p)
}

// Clear removes all registered plugins.
func Clear() {
	mu.Lock()
	defer mu.Unlock()
	plugins = nil
}

// Dispatch calls OnAttachmentSaved on all registered plugins.
func Dispatch(ctx context.Context, event AttachmentEvent) {
	mu.RLock()
	ps := make([]Plugin, len(plugins))
	copy(ps, plugins)
	mu.RUnlock()

	for _, p := range ps {
		if err := p.OnAttachmentSaved(ctx, event); err != nil {
			log.Printf("plugin %s error: %v", p.Name(), err)
		}
	}
}
