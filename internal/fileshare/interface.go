package fileshare

import "context"

// FileShare is the interface for all file storage backends.
type FileShare interface {
	// Test attempts to connect and returns an error if it fails.
	Test(ctx context.Context) error
	// Write saves data to the given relative path, creating directories as needed.
	Write(ctx context.Context, relPath string, data []byte) error
	// Close releases any held connections.
	Close() error
}
