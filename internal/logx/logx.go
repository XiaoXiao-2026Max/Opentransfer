package logx

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	mu       sync.Mutex
	minLevel = LevelInfo
	out      = os.Stdout
)

func SetLevel(name string) {
	mu.Lock()
	defer mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		minLevel = LevelDebug
	case "warn", "warning":
		minLevel = LevelWarn
	case "error":
		minLevel = LevelError
	default:
		minLevel = LevelInfo
	}
}

func levelTag(l Level) string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

func emit(l Level, format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()
	if l < minLevel {
		return
	}
	msg := format
	if len(args) > 0 {
		msg = fmt.Sprintf(format, args...)
	}
	fmt.Fprintf(out, "[%s %s] %s\n", levelTag(l), time.Now().Format("2006-01-02 15:04:05"), msg)
}

type Logger struct{}

func New(_ string) *Logger { return &Logger{} }

func (l *Logger) Debugf(format string, args ...any) { emit(LevelDebug, format, args...) }
func (l *Logger) Infof(format string, args ...any)  { emit(LevelInfo, format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { emit(LevelWarn, format, args...) }
func (l *Logger) Errorf(format string, args ...any) { emit(LevelError, format, args...) }
