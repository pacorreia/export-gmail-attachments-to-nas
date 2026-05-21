package pdf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// PageImage holds a single converted page image.
type PageImage struct {
	Name string
	Data []byte
}

// Converter abstracts PDF-to-image conversion for testability.
type Converter interface {
	ConvertToImages(ctx context.Context, name string, data []byte, dpi int) ([]PageImage, error)
}

// FuncConverter adapts a bare function to the Converter interface.
type FuncConverter func(ctx context.Context, name string, data []byte, dpi int) ([]PageImage, error)

func (f FuncConverter) ConvertToImages(ctx context.Context, name string, data []byte, dpi int) ([]PageImage, error) {
	return f(ctx, name, data, dpi)
}

// Default is the real pdftoppm-backed Converter.
var Default Converter = FuncConverter(ConvertToImages)

// ConvertToImages converts a PDF file (given as bytes) to PNG images using pdftoppm.
// Returns a slice of PageImage, one per page.
func ConvertToImages(ctx context.Context, originalName string, data []byte, dpi int) ([]PageImage, error) {
	if dpi <= 0 {
		dpi = 150
	}

	tmpDir, err := os.MkdirTemp("", "pdf-convert-*")
	if err != nil {
		return nil, fmt.Errorf("mktemp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	inFile := filepath.Join(tmpDir, "input.pdf")
	if err := os.WriteFile(inFile, data, 0600); err != nil {
		return nil, fmt.Errorf("write pdf: %w", err)
	}

	outPrefix := filepath.Join(tmpDir, "page")
	cmd := exec.CommandContext(ctx, "pdftoppm",
		"-r", fmt.Sprintf("%d", dpi),
		"-png",
		inFile,
		outPrefix,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pdftoppm: %w\n%s", err, out)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("readdir: %w", err)
	}

	var pngs []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".png") {
			pngs = append(pngs, filepath.Join(tmpDir, e.Name()))
		}
	}
	sort.Strings(pngs)

	baseName := strings.TrimSuffix(originalName, filepath.Ext(originalName))
	var results []PageImage
	for i, png := range pngs {
		imgData, err := os.ReadFile(png)
		if err != nil {
			return nil, fmt.Errorf("read page %d: %w", i+1, err)
		}
		outName := fmt.Sprintf("%s_page_%03d.png", baseName, i+1)
		results = append(results, PageImage{Name: outName, Data: imgData})
	}
	return results, nil
}
