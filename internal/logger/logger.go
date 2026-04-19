package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu       sync.Mutex
	out      io.Writer
	timezone *time.Location
}

type Mutex struct {
	sync.Mutex
}

func (m *Mutex) Lock()   { m.Mutex.Lock() }
func (m *Mutex) Unlock() { m.Mutex.Unlock() }

func New(timezone string) *Logger {
	tz, err := time.LoadLocation(timezone)
	if err != nil {
		tz = time.UTC
	}
	return &Logger{
		out:      os.Stdout,
		timezone: tz,
	}
}

func (l *Logger) formatTime() string {
	return time.Now().In(l.timezone).Format("2006/01/02 15:04:05")
}

func (l *Logger) Println(v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(l.out, l.formatTime(), fmt.Sprint(v...))
}

func (l *Logger) Printf(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(l.out, l.formatTime(), fmt.Sprintf(format, v...))
}

func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(l.out, l.formatTime(), fmt.Sprintf(format, v...))
	os.Exit(1)
}

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
}

var defaultLogger *Logger

func Init(timezone string) {
	defaultLogger = New(timezone)
}

func Default() *Logger {
	return defaultLogger
}

func Println(v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Println(v...)
	}
}

func Printf(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Printf(format, v...)
	}
}

func Fatalf(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Fatalf(format, v...)
	}
	os.Exit(1)
}

func SetOutput(w io.Writer) {
	if defaultLogger != nil {
		defaultLogger.SetOutput(w)
	}
}
