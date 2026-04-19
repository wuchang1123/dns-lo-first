package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// 日志等级
const (
	Debug = iota
	Info
	Warn
	Error
	Fatal
)

// 日志等级名称
var levelNames = map[int]string{
	Debug: "DEBUG",
	Info:  "INFO",
	Warn:  "WARN",
	Error: "ERROR",
	Fatal: "FATAL",
}

type Logger struct {
	mu       sync.Mutex
	out      io.Writer
	timezone *time.Location
	level    int
}

type Mutex struct {
	sync.Mutex
}

func (m *Mutex) Lock()   { m.Mutex.Lock() }
func (m *Mutex) Unlock() { m.Mutex.Unlock() }

func New(timezone string, level int) *Logger {
	tz, err := time.LoadLocation(timezone)
	if err != nil {
		tz = time.UTC
	}
	return &Logger{
		out:      os.Stdout,
		timezone: tz,
		level:    level,
	}
}

func (l *Logger) formatTime() string {
	return time.Now().In(l.timezone).Format("2006/01/02 15:04:05")
}

func (l *Logger) log(level int, format string, v ...interface{}) {
	if level < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(l.out, l.formatTime(), "["+levelNames[level]+"]", fmt.Sprintf(format, v...))
}

func (l *Logger) Debugf(format string, v ...interface{}) {
	l.log(Debug, format, v...)
}

func (l *Logger) Infof(format string, v ...interface{}) {
	l.log(Info, format, v...)
}

func (l *Logger) Warnf(format string, v ...interface{}) {
	l.log(Warn, format, v...)
}

func (l *Logger) Errorf(format string, v ...interface{}) {
	l.log(Error, format, v...)
}

func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.log(Fatal, format, v...)
	os.Exit(1)
}

func (l *Logger) Println(v ...interface{}) {
	l.Infof("%s", fmt.Sprint(v...))
}

func (l *Logger) Printf(format string, v ...interface{}) {
	l.Infof(format, v...)
}

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
}

var defaultLogger *Logger

func Init(timezone string, level int) {
	defaultLogger = New(timezone, level)
}

func Default() *Logger {
	return defaultLogger
}

func Debugf(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Debugf(format, v...)
	}
}

func Infof(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Infof(format, v...)
	}
}

func Warnf(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Warnf(format, v...)
	}
}

func Errorf(format string, v ...interface{}) {
	if defaultLogger != nil {
		defaultLogger.Errorf(format, v...)
	}
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
