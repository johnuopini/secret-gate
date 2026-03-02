package logger

import (
	"encoding/json"
	"os"
	"time"
)

// Level represents log severity
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
	LevelFatal Level = "fatal"
)

// Entry represents a structured log entry
type Entry struct {
	Timestamp string                 `json:"timestamp"`
	Level     Level                  `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// Logger provides structured JSON logging
type Logger struct {
	fields map[string]interface{}
}

// New creates a new Logger
func New() *Logger {
	return &Logger{
		fields: make(map[string]interface{}),
	}
}

// With returns a new logger with additional fields
func (l *Logger) With(key string, value interface{}) *Logger {
	newFields := make(map[string]interface{})
	for k, v := range l.fields {
		newFields[k] = v
	}
	newFields[key] = value
	return &Logger{fields: newFields}
}

// Debug logs at debug level
func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	l.log(LevelDebug, msg, fields...)
}

// Info logs at info level
func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	l.log(LevelInfo, msg, fields...)
}

// Warn logs at warn level
func (l *Logger) Warn(msg string, fields ...map[string]interface{}) {
	l.log(LevelWarn, msg, fields...)
}

// Error logs at error level
func (l *Logger) Error(msg string, fields ...map[string]interface{}) {
	l.log(LevelError, msg, fields...)
}

// Fatal logs at fatal level and exits
func (l *Logger) Fatal(msg string, fields ...map[string]interface{}) {
	l.log(LevelFatal, msg, fields...)
	os.Exit(1)
}

func (l *Logger) log(level Level, msg string, additionalFields ...map[string]interface{}) {
	entry := Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level,
		Message:   msg,
	}

	// Merge base fields with additional fields
	if len(l.fields) > 0 || len(additionalFields) > 0 {
		merged := make(map[string]interface{})
		for k, v := range l.fields {
			merged[k] = v
		}
		for _, f := range additionalFields {
			for k, v := range f {
				merged[k] = v
			}
		}
		if len(merged) > 0 {
			entry.Fields = merged
		}
	}

	data, _ := json.Marshal(entry)
	os.Stdout.Write(data)
	os.Stdout.Write([]byte("\n"))
}

// F is a shorthand for creating a fields map
func F(keyvals ...interface{}) map[string]interface{} {
	m := make(map[string]interface{})
	for i := 0; i < len(keyvals)-1; i += 2 {
		if key, ok := keyvals[i].(string); ok {
			m[key] = keyvals[i+1]
		}
	}
	return m
}
