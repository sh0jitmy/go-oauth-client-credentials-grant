// Copyright 2026 [Copyright Holder]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author: [YOUR_NAME]

package oauth2

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

const (
	instrumentationName = "github.com/shjtmy/go-oauth-client-credentials-grant/pkg/oauth2"
)

// Telemetry provides OpenTelemetry metrics, traces, and structured audit logging.
type Telemetry struct {
	tracer             trace.Tracer
	meter              metric.Meter
	tokenRequestsTotal metric.Int64Counter
	authChecksTotal    metric.Int64Counter
	tokenDurationSecs  metric.Float64Histogram
	logger             *slog.Logger
}

// NewTelemetry initializes Telemetry using the global or provided OTel providers.
func NewTelemetry(opts ...TelemetryOption) *Telemetry {
	t := &Telemetry{
		tracer: otel.GetTracerProvider().Tracer(instrumentationName),
		meter:  otel.GetMeterProvider().Meter(instrumentationName),
		logger: slog.Default(),
	}

	for _, opt := range opts {
		opt(t)
	}

	// Initialize metrics counters & histograms
	var err error
	t.tokenRequestsTotal, err = t.meter.Int64Counter(
		"oauth2_token_requests_total",
		metric.WithDescription("Total number of OAuth 2.0 token issuance requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		slog.Warn("Failed to create oauth2_token_requests_total metric", "error", err)
	}

	t.authChecksTotal, err = t.meter.Int64Counter(
		"oauth2_auth_checks_total",
		metric.WithDescription("Total number of OAuth 2.0 authorization checks"),
		metric.WithUnit("{check}"),
	)
	if err != nil {
		slog.Warn("Failed to create oauth2_auth_checks_total metric", "error", err)
	}

	t.tokenDurationSecs, err = t.meter.Float64Histogram(
		"oauth2_token_duration_seconds",
		metric.WithDescription("Latency of OAuth 2.0 operations in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		slog.Warn("Failed to create oauth2_token_duration_seconds metric", "error", err)
	}

	return t
}

// TelemetryOption configures the Telemetry instance.
type TelemetryOption func(*Telemetry)

// WithTracer sets a custom tracer.
func WithTracer(tracer trace.Tracer) TelemetryOption {
	return func(t *Telemetry) {
		if tracer != nil {
			t.tracer = tracer
		}
	}
}

// WithMeter sets a custom meter.
func WithMeter(meter metric.Meter) TelemetryOption {
	return func(t *Telemetry) {
		if meter != nil {
			t.meter = meter
		}
	}
}

// WithLogger sets a custom structured logger.
func WithLogger(logger *slog.Logger) TelemetryOption {
	return func(t *Telemetry) {
		if logger != nil {
			t.logger = logger
		}
	}
}

// RecordTokenRequest records metrics, traces, and audit logs for token issuance.
func (t *Telemetry) RecordTokenRequest(ctx context.Context, grantType string, status string, clientID string, resource string, duration time.Duration, err error) {
	attrs := []attribute.KeyValue{
		attribute.String("grant_type", grantType),
		attribute.String("status", status),
	}

	if t.tokenRequestsTotal != nil {
		t.tokenRequestsTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	if t.tokenDurationSecs != nil {
		t.tokenDurationSecs.Record(ctx, duration.Seconds(), metric.WithAttributes(attribute.String("operation", "issue_token")))
	}

	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(
			attribute.String("oauth2.status", status),
			attribute.String("oauth2.grant_type", grantType),
			attribute.String("oauth2.client_id", clientID),
			attribute.String("oauth2.resource", resource),
		)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		} else {
			span.SetStatus(codes.Ok, "token issued")
		}
	}

	// Structured Audit Log
	if status == "ok" {
		t.logger.InfoContext(ctx, "OAuth2 token issued successfully",
			slog.String("log_type", "audit"),
			slog.String("event", "oauth2_token_issued"),
			slog.String("client_id", clientID),
			slog.String("resource", resource),
			slog.String("grant_type", grantType),
			slog.Float64("duration_ms", float64(duration.Microseconds())/1000.0),
		)
	} else {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.logger.WarnContext(ctx, "OAuth2 token issuance rejected",
			slog.String("log_type", "audit"),
			slog.String("event", "oauth2_token_denied"),
			slog.String("status", status),
			slog.String("client_id", clientID),
			slog.String("resource", resource),
			slog.String("grant_type", grantType),
			slog.String("error", errStr),
			slog.Float64("duration_ms", float64(duration.Microseconds())/1000.0),
		)
	}
}

// RecordAuthCheck records metrics, traces, and audit logs for token authorization checks.
func (t *Telemetry) RecordAuthCheck(ctx context.Context, status string, clientID string, targetResource string, reqResource string, path string, method string, err error) {
	attrs := []attribute.KeyValue{
		attribute.String("status", status),
	}

	if t.authChecksTotal != nil {
		t.authChecksTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	}

	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(
			attribute.String("oauth2.status", status),
			attribute.String("oauth2.client_id", clientID),
			attribute.String("oauth2.token_resource", targetResource),
			attribute.String("oauth2.request_resource", reqResource),
		)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		} else {
			span.SetStatus(codes.Ok, "authorized")
		}
	}

	// Structured Audit Log
	if status == "ok" {
		t.logger.InfoContext(ctx, "OAuth2 authorization granted",
			slog.String("log_type", "audit"),
			slog.String("event", "oauth2_auth_granted"),
			slog.String("client_id", clientID),
			slog.String("resource", targetResource),
			slog.String("http_path", path),
			slog.String("http_method", method),
		)
	} else {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		t.logger.WarnContext(ctx, "OAuth2 authorization denied",
			slog.String("log_type", "audit"),
			slog.String("event", "oauth2_auth_denied"),
			slog.String("status", status),
			slog.String("client_id", clientID),
			slog.String("token_resource", targetResource),
			slog.String("request_resource", reqResource),
			slog.String("http_path", path),
			slog.String("http_method", method),
			slog.String("error", errStr),
		)
	}
}
