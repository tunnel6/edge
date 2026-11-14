package log

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	// DefaultLogger Default logger instance
	DefaultLogger = logrus.New()
	outputMu      sync.Mutex
	outputCloser  io.Closer
)

const (
	OutputConsole = "console"
	OutputFile    = "file"
)

func init() {
	setTextFormatter(true)
	// Default logger output is console.
	DefaultLogger.SetOutput(os.Stdout)
	DefaultLogger.SetLevel(logrus.InfoLevel)
	// Add log broadcast hook (for log pushing).
	DefaultLogger.AddHook(NewBroadcastHook())
}

func setTextFormatter(color bool) {
	DefaultLogger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
		ForceColors:     color,
		DisableColors:   !color,
	})
}

func normalizeOutput(output string) string {
	switch strings.ToLower(strings.TrimSpace(output)) {
	case "", OutputConsole, "stdout", "terminal":
		return OutputConsole
	case OutputFile:
		return OutputFile
	default:
		return ""
	}
}

func closeCurrentOutputLocked() error {
	if outputCloser == nil {
		return nil
	}
	closer := outputCloser
	outputCloser = nil
	return closer.Close()
}

func ConfigureOutput(output, filePath string) error {
	rawOutput := output
	output = normalizeOutput(output)
	if output == "" {
		return fmt.Errorf("unsupported log output: %s", rawOutput)
	}

	outputMu.Lock()
	defer outputMu.Unlock()

	if output == OutputConsole {
		if err := closeCurrentOutputLocked(); err != nil {
			return fmt.Errorf("close log file: %w", err)
		}
		DefaultLogger.SetOutput(os.Stdout)
		setTextFormatter(true)
		return nil
	}

	path := strings.TrimSpace(filePath)
	if path == "" {
		return fmt.Errorf("log file path is required when output is file")
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create log dir: %w", err)
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	if err := closeCurrentOutputLocked(); err != nil {
		_ = f.Close()
		return fmt.Errorf("close previous log file: %w", err)
	}

	DefaultLogger.SetOutput(f)
	outputCloser = f
	setTextFormatter(false)
	return nil
}
func SetLogLevel(level logrus.Level) {
	DefaultLogger.SetLevel(level)
}

func SetLogger(l *logrus.Logger) {
	if l == nil {
		return
	}
	outputMu.Lock()
	defer outputMu.Unlock()
	_ = closeCurrentOutputLocked()
	DefaultLogger = l
}

func GetLogger() *logrus.Logger {
	return DefaultLogger
}

func Info(args ...interface{}) {
	DefaultLogger.Info(args...)
}

func Infof(format string, args ...interface{}) {
	DefaultLogger.Infof(format, args...)
}

func Debug(args ...interface{}) {
	DefaultLogger.Debug(args...)
}

func Debugf(format string, args ...interface{}) {
	DefaultLogger.Debugf(format, args...)
}

func Warn(args ...interface{}) {
	DefaultLogger.Warn(args...)
}

func Warnf(format string, args ...interface{}) {
	DefaultLogger.Warnf(format, args...)
}

func Error(args ...interface{}) {
	DefaultLogger.Error(args...)
}

func Errorf(format string, args ...interface{}) {
	DefaultLogger.Errorf(format, args...)
}
