package logger

import (
	"bufio"
	"context"
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
	dir       string
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
		dir:       dir,
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

func (l *Logger) StartJanitor(ctx context.Context, maxAge time.Duration) {
	if maxAge <= 0 {
		return
	}
	go func() {
		timer := time.NewTimer(time.Until(nextMidnight(l.loc)))
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				l.cleanOldLogs(maxAge)
				timer.Reset(time.Until(nextMidnight(l.loc)))
			case <-ctx.Done():
				return
			}
		}
	}()
}

func nextMidnight(loc *time.Location) time.Time {
	now := time.Now().In(loc)
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, loc)
	return next
}

func (l *Logger) cleanOldLogs(maxAge time.Duration) {
	cutoff := time.Now().In(l.loc).Add(-maxAge)
	l.mu.Lock()
	if removed, err := trimLogFile(filepath.Join(l.dir, "lo-first.log"), cutoff, l.loc); err == nil && removed > 0 {
		l.log.Printf("%s [info] cleaned log file=lo-first.log removed=%d max_age=%s", time.Now().In(l.loc).Format("2006-01-02 15:04:05"), removed, maxAge)
	}
	l.mu.Unlock()

	l.queryMu.Lock()
	if removed, err := trimLogFile(filepath.Join(l.dir, "query.log"), cutoff, l.loc); err == nil && removed > 0 {
		l.log.Printf("%s [info] cleaned log file=query.log removed=%d max_age=%s", time.Now().In(l.loc).Format("2006-01-02 15:04:05"), removed, maxAge)
	}
	l.queryMu.Unlock()
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

func trimLogFile(path string, cutoff time.Time, loc *time.Location) (int, error) {
	in, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer in.Close()

	tmp := path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}

	removed := 0
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Text()
		if isOldLogLine(line, cutoff, loc) {
			removed++
			continue
		}
		if _, err := out.WriteString(line + "\n"); err != nil {
			_ = out.Close()
			return 0, err
		}
	}
	if err := scanner.Err(); err != nil {
		_ = out.Close()
		return 0, err
	}
	if err := out.Close(); err != nil {
		return 0, err
	}
	if removed == 0 {
		_ = os.Remove(tmp)
		return 0, nil
	}
	return removed, os.Rename(tmp, path)
}

func isOldLogLine(line string, cutoff time.Time, loc *time.Location) bool {
	if len(line) < len("2006-01-02 15:04:05") {
		return false
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", line[:len("2006-01-02 15:04:05")], loc)
	if err != nil {
		return false
	}
	return t.Before(cutoff)
}
