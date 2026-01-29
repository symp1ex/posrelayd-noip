package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	logDir     = "data/logs"
	retainDays = 5
	logLevel   = "debug"
)

type RotatingWriter struct {
	mu         sync.Mutex
	file       *os.File
	name       string
	currentDay string
}

func NewRotatingWriter(name string) *RotatingWriter {
	os.MkdirAll(logDir, 0755)

	w := &RotatingWriter{name: name}

	// Проверяем существующий файл
	path := filepath.Join(logDir, fmt.Sprintf("%s.log", name))
	if info, err := os.Stat(path); err == nil {
		fileDay := info.ModTime().Format("2006-01-02")
		today := time.Now().Format("2006-01-02")
		if fileDay != today {
			// Переименуем старый файл с датой
			newPath := filepath.Join(logDir, fmt.Sprintf("%s.log.%s", name, fileDay))
			os.Rename(path, newPath)
		}
	}

	w.rotateIfNeeded()
	return w
}

func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.rotateIfNeeded()
	return w.file.Write(p)
}

func (w *RotatingWriter) rotateIfNeeded() {
	today := time.Now().Format("2006-01-02")
	if w.file != nil && w.currentDay == today {
		return
	}

	// Если файл открыт и это новый день, закрываем старый
	if w.file != nil {
		w.file.Close()

		// Переименовываем старый файл с датой
		oldPath := filepath.Join(logDir, fmt.Sprintf("%s.log", w.name))
		newPath := filepath.Join(logDir, fmt.Sprintf("%s.log.%s", w.name, w.currentDay))
		os.Rename(oldPath, newPath)
	}

	// Открываем новый текущий лог
	path := filepath.Join(logDir, fmt.Sprintf("%s.log", w.name))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	w.file = file
	w.currentDay = today

	w.cleanupOldLogs()
}

func (w *RotatingWriter) cleanupOldLogs() {
	files, _ := filepath.Glob(filepath.Join(logDir, fmt.Sprintf("%s.log.*", w.name)))
	cutoff := time.Now().AddDate(0, 0, -retainDays)

	for _, f := range files {
		info, err := os.Stat(f)
		if err == nil && info.ModTime().Before(cutoff) {
			os.Remove(f)
		}
	}
}
