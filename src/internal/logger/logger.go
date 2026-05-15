package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Config struct {
	FilePath   string
	MaxSizeMB  int
	MaxAgeDays int
	MaxFiles   int
}

var level = new(slog.LevelVar)

func Init(cfg Config) error {
	level.Set(slog.LevelInfo)

	if cfg.FilePath == "" {
		h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
		slog.SetDefault(slog.New(h))
		return nil
	}

	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 10
	}
	if cfg.MaxAgeDays <= 0 {
		cfg.MaxAgeDays = 7
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = 5
	}

	if err := os.MkdirAll(filepath.Dir(cfg.FilePath), 0755); err != nil {
		return fmt.Errorf("logger: create log dir: %w", err)
	}

	w := &rotatingWriter{
		dir:      filepath.Dir(cfg.FilePath),
		basename: filepath.Base(cfg.FilePath),
		maxSize:  int64(cfg.MaxSizeMB) * 1024 * 1024,
		maxAge:   time.Duration(cfg.MaxAgeDays) * 24 * time.Hour,
		maxFiles: cfg.MaxFiles,
	}

	if err := w.openFile(); err != nil {
		return fmt.Errorf("logger: open log file: %w", err)
	}
	w.cleanupOld()

	mw := io.MultiWriter(os.Stdout, w)
	h := slog.NewJSONHandler(mw, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))
	return nil
}

type rotatingWriter struct {
	mu       sync.Mutex
	dir      string
	basename string
	maxSize  int64
	maxAge   time.Duration
	maxFiles int
	file     *os.File
	size     int64
}

func (w *rotatingWriter) openFile() error {
	path := filepath.Join(w.dir, w.basename)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.file = f
	w.size = info.Size()
	return nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingWriter) rotate() error {
	if w.file != nil {
		w.file.Close()
		w.file = nil
	}
	oldPath := filepath.Join(w.dir, w.basename)
	ts := time.Now().Format("20060102-150405")
	rotatedPath := filepath.Join(w.dir, w.basename+"."+ts)
	os.Rename(oldPath, rotatedPath)
	if err := w.openFile(); err != nil {
		return err
	}
	w.cleanupOld()
	return nil
}

func (w *rotatingWriter) cleanupOld() {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}
	prefix := w.basename + "."
	var rotated []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > w.maxAge {
			os.Remove(filepath.Join(w.dir, e.Name()))
		} else {
			rotated = append(rotated, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(rotated)))
	for i := w.maxFiles; i < len(rotated); i++ {
		os.Remove(filepath.Join(w.dir, rotated[i]))
	}
}

func Info(msg string, attrs ...any)  { slog.Info(msg, attrs...) }
func Warn(msg string, attrs ...any)  { slog.Warn(msg, attrs...) }
func Error(msg string, attrs ...any) { slog.Error(msg, attrs...) }
