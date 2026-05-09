package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type logger struct {
	mu       sync.Mutex
	level    int
	loc      *time.Location
	baseFile *os.File
	query    *os.File
}

func newLogger(dir, queryFile, level string, loc *time.Location) (*logger, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(queryFile), 0o755); err != nil {
		return nil, err
	}
	base, err := os.OpenFile(filepath.Join(dir, "dns-lo-first.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	query, err := os.OpenFile(queryFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	return &logger{level: parseLogLevel(level), loc: loc, baseFile: base, query: query}, nil
}

func parseLogLevel(level string) int {
	switch strings.ToLower(level) {
	case "debug":
		return 0
	case "warn":
		return 2
	case "error":
		return 3
	default:
		return 1
	}
}

func (l *logger) Close() {
	if l == nil {
		return
	}
	_ = l.baseFile.Close()
	_ = l.query.Close()
}

func (l *logger) logf(level int, name, format string, args ...any) {
	if level < l.level {
		return
	}
	line := fmt.Sprintf("%s %-5s %s\n", l.now(), name, fmt.Sprintf(format, args...))
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = os.Stdout.WriteString(line)
	_, _ = l.baseFile.WriteString(line)
}

func (l *logger) now() string {
	return time.Now().In(l.loc).Format("06-01-02 15:04:05.000")
}

func (l *logger) Debugf(format string, args ...any) { l.logf(0, "DEBUG", format, args...) }
func (l *logger) Infof(format string, args ...any)  { l.logf(1, "INFO", format, args...) }
func (l *logger) Warnf(format string, args ...any)  { l.logf(2, "WARN", format, args...) }
func (l *logger) Errorf(format string, args ...any) { l.logf(3, "ERROR", format, args...) }
func (l *logger) Fatalf(format string, args ...any) {
	l.logf(4, "FATAL", format, args...)
	os.Exit(1)
}

func (l *logger) Queryf(format string, args ...any) {
	line := fmt.Sprintf("%s %s\n", l.now(), fmt.Sprintf(format, args...))
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.query.WriteString(line)
}
