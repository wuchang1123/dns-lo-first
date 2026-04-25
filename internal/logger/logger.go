package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
	Fatal
)

type Logger struct {
	mu        sync.Mutex
	queryMu   sync.Mutex
	level     Level
	loc       *time.Location
	log       *log.Logger
	queryLog  *log.Logger
	file      *os.File
	queryFile *os.File
}

func New(level, timezone, dir string) (*Logger, error) {
	lvl := parseLevel(level)
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		loc = time.Local
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "lo-first.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	qf, err := os.OpenFile(filepath.Join(dir, "query.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Logger{
		level:     lvl,
		loc:       loc,
		log:       log.New(io.MultiWriter(os.Stdout, f), "", 0),
		queryLog:  log.New(qf, "", 0),
		file:      f,
		queryFile: qf,
	}, nil
}

func (l *Logger) Close() error {
	var err error
	if l.file != nil {
		err = l.file.Close()
	}
	if l.queryFile != nil {
		if closeErr := l.queryFile.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

func (l *Logger) Debugf(format string, args ...any) { l.printf(Debug, "debug", format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.printf(Info, "info", format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.printf(Warn, "warn", format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.printf(Error, "error", format, args...) }

func (l *Logger) Fatalf(format string, args ...any) {
	l.printf(Fatal, "fatal", format, args...)
	os.Exit(1)
}

func (l *Logger) Queryf(format string, args ...any) {
	l.queryMu.Lock()
	defer l.queryMu.Unlock()
	now := time.Now().In(l.loc).Format("2006-01-02 15:04:05")
	l.queryLog.Printf("%s %s", now, fmt.Sprintf(format, args...))
}

func (l *Logger) printf(level Level, label, format string, args ...any) {
	if level < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().In(l.loc).Format("2006-01-02 15:04:05")
	l.log.Printf("%s [%s] %s", now, label, fmt.Sprintf(format, args...))
}

func parseLevel(level string) Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return Debug
	case "warn", "warning":
		return Warn
	case "error":
		return Error
	case "fatal":
		return Fatal
	default:
		return Info
	}
}
