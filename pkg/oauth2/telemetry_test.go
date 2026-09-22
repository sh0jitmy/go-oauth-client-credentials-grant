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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestTelemetry_Options_And_Execution(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	tracerProvider := sdktrace.NewTracerProvider()
	tracer := tracerProvider.Tracer("test")

	meterProvider := sdkmetric.NewMeterProvider()
	meter := meterProvider.Meter("test")

	telem := NewTelemetry(
		WithTracer(tracer),
		WithMeter(meter),
		WithLogger(logger),
	)
	assert.NotNil(t, telem)

	ctx, span := tracer.Start(context.Background(), "test_span")
	defer span.End()

	// 1. RecordTokenRequest - OK
	telem.RecordTokenRequest(ctx, "client_credentials", "ok", "client-1", "https://api.example.com/v1/certs/1", 10*time.Millisecond, nil)
	assert.Contains(t, buf.String(), "oauth2_token_issued")
	assert.Contains(t, buf.String(), "audit")

	// 2. RecordTokenRequest - Error
	buf.Reset()
	telem.RecordTokenRequest(ctx, "client_credentials", "invalid_client", "client-1", "https://api.example.com/v1/certs/1", 5*time.Millisecond, errors.New("auth failed"))
	assert.Contains(t, buf.String(), "oauth2_token_denied")

	// 3. RecordAuthCheck - OK
	buf.Reset()
	telem.RecordAuthCheck(ctx, "ok", "client-1", "https://api.example.com/v1/certs/1", "https://api.example.com/v1/certs/1", "/v1/certs/1", "GET", nil)
	assert.Contains(t, buf.String(), "oauth2_auth_granted")

	// 4. RecordAuthCheck - Error
	buf.Reset()
	telem.RecordAuthCheck(ctx, "invalid_token", "", "", "", "/v1/certs/1", "GET", errors.New("token expired"))
	assert.Contains(t, buf.String(), "oauth2_auth_denied")
}

func TestTelemetry_NilOptions(t *testing.T) {
	t.Parallel()

	// With nil options to test nil guards
	telem := NewTelemetry(
		WithTracer(nil),
		WithMeter(nil),
		WithLogger(nil),
	)
	assert.NotNil(t, telem)

	ctx := context.Background()
	// Should not panic even without active span
	telem.RecordTokenRequest(ctx, "client_credentials", "ok", "c1", "res1", time.Millisecond, nil)
	telem.RecordTokenRequest(ctx, "client_credentials", "error", "c1", "res1", time.Millisecond, nil)
	telem.RecordAuthCheck(ctx, "ok", "c1", "res1", "res1", "/path", "GET", nil)
	telem.RecordAuthCheck(ctx, "error", "c1", "res1", "res1", "/path", "GET", nil)
}

type errorMeter struct {
	metric.Meter
}

func (m *errorMeter) Int64Counter(name string, options ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	return nil, errors.New("counter creation failed")
}

func (m *errorMeter) Float64Histogram(name string, options ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	return nil, errors.New("histogram creation failed")
}

func TestTelemetry_MeterError(t *testing.T) {
	t.Parallel()

	telem := NewTelemetry(WithMeter(&errorMeter{}))
	assert.NotNil(t, telem)
	assert.Nil(t, telem.tokenRequestsTotal)
	assert.Nil(t, telem.authChecksTotal)
	assert.Nil(t, telem.tokenDurationSecs)

	// Ensure methods handle nil metric instruments safely
	ctx := context.Background()
	telem.RecordTokenRequest(ctx, "client_credentials", "ok", "c1", "res1", time.Millisecond, nil)
	telem.RecordAuthCheck(ctx, "ok", "c1", "res1", "res1", "/path", "GET", nil)
}
