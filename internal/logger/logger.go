package logger

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

var (
	loggers   = make(map[string]*slog.Logger)
	mu        sync.Mutex
	Websocket Logger
)

type Logger struct {
	*slog.Logger
}

func levelFromString(level string) slog.Level {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func (l Logger) Infof(format string, args ...any) {
	l.Info(fmt.Sprintf(format, args...))
}

func (l Logger) Debugf(format string, args ...any) {
	l.Debug(fmt.Sprintf(format, args...))
}

func (l Logger) Warnf(format string, args ...any) {
	l.Warn(fmt.Sprintf(format, args...))
}

func (l Logger) Errorf(format string, args ...any) {
	l.Error(fmt.Sprintf(format, args...))
}

// Get возвращает логгер по имени файла
func Get(name string) *slog.Logger {
	mu.Lock()
	defer mu.Unlock()

	if l, ok := loggers[name]; ok {
		return l
	}

	writer := NewRotatingWriter(name)
	handler := NewPlainHandler(writer, levelFromString(logLevel))

	logger := slog.New(handler)
	loggers[name] = logger
	return logger
}

func init() {
	Websocket = Logger{Get("websocket")}
}
