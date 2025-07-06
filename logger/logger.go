// Copyright 2023 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/common/promslog"
)

// LogFormat represents the format of the logs
type LogFormat string

const (
	// DefaultFormat is the standard logging format
	DefaultFormat LogFormat = "default"
	// JSONFormat outputs logs in JSON format
	JSONFormat LogFormat = "json"
)

// FormatOptions contains all valid log format options
var FormatOptions = []string{string(DefaultFormat), string(JSONFormat)}

// Config represents the configuration for the logger
type Config struct {
	Format         LogFormat
	promslogConfig *promslog.Config
}

// NewConfig creates a new logger config with default values
func NewConfig(promslogConfig *promslog.Config) *Config {
	return &Config{
		Format:         DefaultFormat,
		promslogConfig: promslogConfig,
	}
}

// JSONHandler is a slog.Handler that formats log records as JSON
type JSONHandler struct {
	mu     *sync.Mutex
	w      io.Writer
	groups []string
	attrs  []slog.Attr
}

// NewJSONHandler creates a new JSONHandler
func NewJSONHandler(w io.Writer) *JSONHandler {
	return &JSONHandler{
		mu: &sync.Mutex{},
		w:  w,
	}
}

// Enabled implements slog.Handler.
func (h *JSONHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

// Buffer for storing partial log messages that need to be combined
var (
	partialLogMu     sync.Mutex
	partialLogBuffer = make(map[string]string)
)

// Handle implements slog.Handler.
func (h *JSONHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Get the main message
	message := r.Message

	// Extract all attributes for better message processing
	attrs := make(map[string]string)
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = fmt.Sprintf("%v", a.Value.Any())
		return true
	})

	// Special handling for specific log messages to make them more readable
	if message == "Starting blackbox_exporter" {
		// For the startup message, we'll include version info if available
		version := attrs["version"]
		branch := attrs["branch"]
		revision := attrs["revision"]

		// Store this as a partial message to be combined with build info
		partialLogMu.Lock()
		partialLogBuffer["startup"] = fmt.Sprintf("Server starting with version %s %s %s",
			version, branch, revision)
		partialLogMu.Unlock()

		// Don't output anything yet, wait for the build info message
		return nil
	} else if strings.Contains(message, "go=") && strings.Contains(message, "platform=") {
		// This is the build info message that follows the startup message
		partialLogMu.Lock()
		startupMsg, exists := partialLogBuffer["startup"]
		delete(partialLogBuffer, "startup") // Clear the buffer
		partialLogMu.Unlock()

		if exists {
			// Combine with the previous startup message
			message = fmt.Sprintf("%s (%s)", startupMsg, message)
		}
	} else if strings.Contains(message, "Listening on") {
		// For the listening message, extract the address
		address := attrs["address"]
		if address != "" {
			// Store this as a partial message to be combined with the path
			partialLogMu.Lock()
			partialLogBuffer["http"] = address
			partialLogMu.Unlock()

			// Don't output anything yet, wait for the path message
			return nil
		}
	} else if message == "/" || message == "/metrics" || strings.HasPrefix(message, "/probe") {
		// This is likely the path that follows the listening message
		partialLogMu.Lock()
		address, exists := partialLogBuffer["http"]
		delete(partialLogBuffer, "http") // Clear the buffer
		partialLogMu.Unlock()

		if exists {
			// Combine with the previous address
			message = fmt.Sprintf("%s%s", address, message)
		}
	} else if message == "TLS is disabled." {
		message = "TLS is disabled"
	}

	severity := getSeverityFromLevel(r.Level)

	// Create log entry with ONLY message and severity
	logEntry := map[string]string{
		"message":  message,
		"severity": severity,
	}

	jsonBytes, err := json.Marshal(logEntry)
	if err != nil {
		return err
	}

	_, err = h.w.Write(append(jsonBytes, '\n'))
	return err
}

// WithAttrs implements slog.Handler.
func (h *JSONHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)

	return &JSONHandler{
		mu:     h.mu,
		w:      h.w,
		groups: h.groups,
		attrs:  newAttrs,
	}
}

// WithGroup implements slog.Handler.
func (h *JSONHandler) WithGroup(name string) slog.Handler {
	newGroups := make([]string, len(h.groups)+1)
	copy(newGroups, h.groups)
	newGroups[len(h.groups)] = name

	return &JSONHandler{
		mu:     h.mu,
		w:      h.w,
		groups: newGroups,
		attrs:  h.attrs,
	}
}

// getSeverityFromLevel converts slog.Level to our severity string
func getSeverityFromLevel(level slog.Level) string {
	if level >= slog.LevelError {
		return "ERROR"
	}
	return "NORMAL"
}

// New creates a new logger with the specified format
func New(config *Config) *slog.Logger {
	if config.Format == JSONFormat {
		handler := NewJSONHandler(os.Stderr)
		return slog.New(handler)
	}

	// Use the standard promslog logger for default format
	return promslog.New(config.promslogConfig)
}

// AddFlags adds the flags used by this package to the Kingpin application
func AddFlags(a *kingpin.Application, config *Config) {
	a.Flag("log.output-format", fmt.Sprintf("Output format of log messages. One of: [%s]", strings.Join(FormatOptions, ", "))).Default(string(DefaultFormat)).EnumVar((*string)(&config.Format), FormatOptions...)
}
