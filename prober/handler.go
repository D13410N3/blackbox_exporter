// Copyright 2016 The Prometheus Authors
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

package prober

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/promslog"
	"gopkg.in/yaml.v2"
)

var (
	Probers = map[string]ProbeFn{
		"http": ProbeHTTP,
		"tcp":  ProbeTCP,
		"icmp": ProbeICMP,
		"dns":  ProbeDNS,
		"grpc": ProbeGRPC,
	}
)

func Handler(w http.ResponseWriter, r *http.Request, c *config.Config, logger *slog.Logger, rh *ResultHistory, timeoutOffset float64, params url.Values,
	moduleUnknownCounter prometheus.Counter,
	logLevel, logLevelProber *promslog.Level) {

	if params == nil {
		params = r.URL.Query()
	}
	moduleName := params.Get("module")
	if moduleName == "" {
		moduleName = "http_2xx"
	}
	module, ok := c.Modules[moduleName]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown module %q", moduleName), http.StatusBadRequest)
		logger.Debug("Unknown module", "module", moduleName)
		if moduleUnknownCounter != nil {
			moduleUnknownCounter.Add(1)
		}
		return
	}

	timeoutSeconds, err := getTimeout(r, module, timeoutOffset)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse timeout from Prometheus header: %s", err), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeoutSeconds*float64(time.Second)))
	defer cancel()
	r = r.WithContext(ctx)

	probeSuccessGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_success",
		Help: "Displays whether or not the probe was a success",
	})
	probeDurationGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	})

	target := params.Get("target")
	if target == "" {
		http.Error(w, "Target parameter is missing", http.StatusBadRequest)
		return
	}

	prober, ok := Probers[module.Prober]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown prober %q", module.Prober), http.StatusBadRequest)
		return
	}

	hostname := params.Get("hostname")
	if module.Prober == "http" && hostname != "" {
		err = setHTTPHost(hostname, &module)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if module.Prober == "tcp" && hostname != "" {
		if module.TCP.TLSConfig.ServerName == "" {
			module.TCP.TLSConfig.ServerName = hostname
		}
	}

	// Create a buffer to capture all logs for failure analysis
	var logBuffer bytes.Buffer
	bufferLogger := promslog.New(&promslog.Config{Writer: &logBuffer, Level: logLevel})
	slLogger := bufferLogger.With("module", moduleName, "target", target)

	// Don't log the beginning of the probe to the main logger
	slLogger.Info("Beginning probe", "probe", module.Prober, "timeout_seconds", timeoutSeconds)

	start := time.Now()
	registry := prometheus.NewRegistry()
	registry.MustRegister(probeSuccessGauge)
	registry.MustRegister(probeDurationGauge)
	success := prober(ctx, target, module, registry, slLogger)
	duration := time.Since(start).Seconds()
	probeDurationGauge.Set(duration)

	// Only log the final result
	if success {
		probeSuccessGauge.Set(1)
		// For successful probes, only log the final result without intermediate steps
		logger.Info(fmt.Sprintf("Probe %s using module %s was successful", target, moduleName))
	} else {
		// For failed probes, extract the failure reason and log it
		reason := extractFailureReason(&logBuffer)
		var resultMsg string
		if reason != "" {
			resultMsg = fmt.Sprintf("Probe %s using module %s failed with reason: %s", target, moduleName, reason)
		} else {
			resultMsg = fmt.Sprintf("Probe %s using module %s failed", target, moduleName)
		}
		// Log the result in the specified JSON format
		logger.Info(resultMsg)
	}

	debugOutput := DebugOutput(&module, &logBuffer, registry)
	rh.Add(moduleName, target, debugOutput, success)

	if r.URL.Query().Get("debug") == "true" {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(debugOutput))
		return
	}

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func setHTTPHost(hostname string, module *config.Module) error {
	// By creating a new hashmap and copying values there we
	// ensure that the initial configuration remain intact.
	headers := make(map[string]string)
	if module.HTTP.Headers != nil {
		for name, value := range module.HTTP.Headers {
			if textproto.CanonicalMIMEHeaderKey(name) == "Host" && value != hostname {
				return fmt.Errorf("host header defined both in module configuration (%s) and with URL-parameter 'hostname' (%s)", value, hostname)
			}
			headers[name] = value
		}
	}
	headers["Host"] = hostname
	module.HTTP.Headers = headers
	return nil
}

type scrapeLogger struct {
	next           *slog.Logger
	buffer         bytes.Buffer
	bufferLogger   *slog.Logger
	logLevelProber *promslog.Level
}

// Handle writes the provided log record to the internal logger, and then to
// the internal bufferLogger for use with serving debug output. It implements
// slog.Handler.
func (sl *scrapeLogger) Handle(ctx context.Context, r slog.Record) error {
	level := getSlogLevel(sl.logLevelProber.String())

	// Collect attributes from record so we can log them directly. We
	// hijack log calls to the scrapeLogger and override the level from the
	// original log call with the level set via the `--log.prober` flag.
	attrs := make([]slog.Attr, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	sl.next.LogAttrs(ctx, level, r.Message, attrs...)
	sl.bufferLogger.LogAttrs(ctx, level, r.Message, attrs...)

	return nil
}

// WithAttrs adds the provided attributes to the scrapeLogger's internal logger and
// bufferLogger. It implements slog.Handler.
func (sl *scrapeLogger) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &scrapeLogger{
		next:           slog.New(sl.next.Handler().WithAttrs(attrs)),
		buffer:         sl.buffer,
		bufferLogger:   slog.New(sl.bufferLogger.Handler().WithAttrs(attrs)),
		logLevelProber: sl.logLevelProber,
	}
}

// WithGroup adds the provided group name to the scrapeLogger's internal logger
// and bufferLogger. It implements slog.Handler.
func (sl *scrapeLogger) WithGroup(name string) slog.Handler {
	return &scrapeLogger{
		next:           slog.New(sl.next.Handler().WithGroup(name)),
		buffer:         sl.buffer,
		bufferLogger:   slog.New(sl.bufferLogger.Handler().WithGroup(name)),
		logLevelProber: sl.logLevelProber,
	}
}

// Enabled implements slog.Handler.
func (sl *scrapeLogger) Enabled(ctx context.Context, level slog.Level) bool {
	// We want to capture all logs for potential failure analysis
	return true
}

func newScrapeLogger(logger *slog.Logger, module string, target string, logLevel, logLevelProber *promslog.Level) *scrapeLogger {
	if logLevelProber == nil {
		logLevelProber = promslog.NewLevel()
	}
	sl := &scrapeLogger{
		next:           logger.With("module", module, "target", target),
		buffer:         bytes.Buffer{},
		logLevelProber: logLevelProber,
	}
	bl := promslog.New(&promslog.Config{Writer: &sl.buffer, Level: logLevel})
	sl.bufferLogger = bl.With("module", module, "target", target)
	return sl
}

func getSlogLevel(level string) slog.Level {
	switch level {
	case "info":
		return slog.LevelInfo
	case "debug":
		return slog.LevelDebug
	case "error":
		return slog.LevelError
	case "warn":
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

// DebugOutput returns plaintext debug output for a probe.
func DebugOutput(module *config.Module, logBuffer *bytes.Buffer, registry *prometheus.Registry) string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "Logs for the probe:\n")
	logBuffer.WriteTo(buf)
	fmt.Fprintf(buf, "\n\n\nMetrics that would have been returned:\n")
	mfs, err := registry.Gather()
	if err != nil {
		fmt.Fprintf(buf, "Error gathering metrics: %s\n", err)
	}
	for _, mf := range mfs {
		expfmt.MetricFamilyToText(buf, mf)
	}
	fmt.Fprintf(buf, "\n\n\nModule configuration:\n")
	c, err := yaml.Marshal(module)
	if err != nil {
		fmt.Fprintf(buf, "Error marshalling config: %s\n", err)
	}
	buf.Write(c)

	return buf.String()
}

// extractFailureReason attempts to extract a meaningful failure reason from the log buffer
func extractFailureReason(buffer *bytes.Buffer) string {
	// Make a copy of the buffer to avoid modifying the original
	bufferCopy := bytes.NewBuffer(buffer.Bytes())

	// First, look for HTTP status code issues which are common
	scanner := bufio.NewScanner(bufferCopy)
	for scanner.Scan() {
		line := scanner.Text()

		// Check for HTTP status code issues
		if strings.Contains(line, "Invalid HTTP response status code") {
			// Extract status code from the line
			statusCodeMatch := regexp.MustCompile(`status_code=([0-9]+)`).FindStringSubmatch(line)
			if len(statusCodeMatch) > 1 {
				return fmt.Sprintf("expected HTTP status 2xx but got %s", statusCodeMatch[1])
			}

			// Fallback if we can't extract the status code
			return "expected HTTP status 2xx but got a different status code"
		}

		// Check for DNS resolution errors
		if strings.Contains(line, "Error resolving address") {
			// Try to extract the specific error
			errMatch := regexp.MustCompile(`err="([^"]+)"`).FindStringSubmatch(line)
			if len(errMatch) > 1 {
				return errMatch[1]
			}
			return "DNS resolution failed"
		}

		// Look for HTTP redirects
		if strings.Contains(line, "following redirects") && strings.Contains(line, "got 302") {
			return "received HTTP 302 redirect when expecting direct response"
		}
	}

	// Reset buffer for next scan
	bufferCopy = bytes.NewBuffer(buffer.Bytes())

	// Look for specific error patterns in the logs
	specificErrors := []struct {
		pattern string
		message string
	}{
		{"connection refused", "connection refused"},
		{"timeout", "connection timed out"},
		{"context deadline exceeded", "request timed out"},
		{"no such host", "DNS resolution failed: no such host"},
		{"TLS handshake error", "TLS handshake failed"},
		{"certificate has expired", "SSL certificate has expired"},
		{"certificate is not valid", "SSL certificate is not valid"},
		{"x509: certificate", "SSL certificate validation error"},
		{"connection reset by peer", "connection reset by peer"},
		{"no route to host", "no route to host"},
		{"dial tcp", "TCP connection failed"},
		{"lookup failed", "DNS lookup failed"},
	}

	// Scan for specific error patterns
	scanner = bufio.NewScanner(bufferCopy)
	for scanner.Scan() {
		line := scanner.Text()

		// Check for specific error messages
		for _, errDef := range specificErrors {
			if strings.Contains(line, errDef.pattern) {
				return errDef.message
			}
		}
	}

	// If no specific reason found, do a more general search
	bufferCopy = bytes.NewBuffer(buffer.Bytes())
	scanner = bufio.NewScanner(bufferCopy)
	for scanner.Scan() {
		line := scanner.Text()

		// Look for any error messages
		if strings.Contains(line, "error") || strings.Contains(line, "Error") || strings.Contains(line, "ERROR") ||
			strings.Contains(line, "failed") || strings.Contains(line, "Failed") || strings.Contains(line, "FAILED") {
			// Try to extract the msg field from the log line
			msgMatch := regexp.MustCompile(`msg="([^"]+)"`).FindStringSubmatch(line)
			if len(msgMatch) > 1 {
				return msgMatch[1]
			}

			// Extract the message part from JSON format
			messageParts := strings.SplitN(line, "\"message\":", 2)
			if len(messageParts) > 1 {
				// Extract the message part
				message := messageParts[1]
				// Remove quotes and other JSON parts
				message = strings.TrimPrefix(message, "\"")
				endIndex := strings.Index(message, "\",")
				if endIndex > 0 {
					message = message[:endIndex]
				}
				return message
			}
		}
	}

	// If no specific reason found, return empty string
	return ""
}

func getTimeout(r *http.Request, module config.Module, offset float64) (timeoutSeconds float64, err error) {
	// If a timeout is configured via the Prometheus header, add it to the request.
	if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
		var err error
		timeoutSeconds, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, err
		}
	}
	if timeoutSeconds == 0 {
		timeoutSeconds = 120
	}

	var maxTimeoutSeconds = timeoutSeconds - offset
	if module.Timeout.Seconds() < maxTimeoutSeconds && module.Timeout.Seconds() > 0 || maxTimeoutSeconds < 0 {
		timeoutSeconds = module.Timeout.Seconds()
	} else {
		timeoutSeconds = maxTimeoutSeconds
	}

	return timeoutSeconds, nil
}
