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

package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shjtmy/go-oauth-client-credentials-grant/pkg/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_New_And_SetNowFunc(t *testing.T) {
	t.Parallel()

	// Default config
	c := New(Config{
		ServerURL: "http://localhost:8080",
	})
	assert.NotNil(t, c)
	assert.Equal(t, tokenExpiryBuffer, c.expiryBuffer)
	assert.NotNil(t, c.httpClient)

	// Custom config
	fixedTime := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	c2 := New(Config{
		ServerURL:    "http://localhost:8080",
		ExpiryBuffer: 60 * time.Second,
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
	})
	assert.Equal(t, 60*time.Second, c2.expiryBuffer)

	c2.SetNowFunc(func() time.Time { return fixedTime })
	assert.Equal(t, fixedTime, c2.nowFunc())

	// Nil guard
	c2.SetNowFunc(nil)
	assert.Equal(t, fixedTime, c2.nowFunc())
}

func TestClient_RegisterClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/oauth/clients", r.URL.Path)
			assert.Equal(t, http.MethodPost, r.Method)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(oauth2.RegisterClientResponse{ //nolint:gosec // false positive for test registration response
				ClientID:     "client-123",
				ClientSecret: "sec-456",
				Name:         "Client A",
			})
		}))
		defer ts.Close()

		c := New(Config{ServerURL: ts.URL})
		resp, err := c.RegisterClient(ctx, &oauth2.RegisterClientRequest{Name: "Client A"})
		require.NoError(t, err)
		assert.Equal(t, "client-123", resp.ClientID)
		assert.Equal(t, "sec-456", resp.ClientSecret)
	})

	t.Run("nil request", func(t *testing.T) {
		t.Parallel()
		c := New(Config{ServerURL: "http://localhost:8080"})
		_, err := c.RegisterClient(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "request cannot be nil")
	})

	t.Run("invalid server url", func(t *testing.T) {
		t.Parallel()
		c := New(Config{ServerURL: "http://[::1]:namedport"})
		_, err := c.RegisterClient(ctx, &oauth2.RegisterClientRequest{Name: "Client"})
		require.Error(t, err)
	})

	t.Run("network error", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		ts.Close() // Close immediately to trigger connection refused

		c := New(Config{ServerURL: ts.URL})
		_, err := c.RegisterClient(ctx, &oauth2.RegisterClientRequest{Name: "Client"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to call register endpoint")
	})

	t.Run("server returned non-201", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad_request"}`))
		}))
		defer ts.Close()

		c := New(Config{ServerURL: ts.URL})
		_, err := c.RegisterClient(ctx, &oauth2.RegisterClientRequest{Name: "Client"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 400")
	})

	t.Run("invalid json response", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`invalid-json`))
		}))
		defer ts.Close()

		c := New(Config{ServerURL: ts.URL})
		_, err := c.RegisterClient(ctx, &oauth2.RegisterClientRequest{Name: "Client"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode register response")
	})

	t.Run("marshal error", func(t *testing.T) {
		t.Parallel()
		c := New(Config{ServerURL: "http://localhost:8080"})
		c.jsonMarshal = func(v any) ([]byte, error) {
			return nil, errors.New("mock marshal error")
		}
		_, err := c.RegisterClient(ctx, &oauth2.RegisterClientRequest{Name: "Client"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal register request")
	})
}

func TestClient_GetToken_DoubleCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	c := New(Config{
		ServerURL:    "http://localhost:8080",
		ClientID:     "client-1",
		ClientSecret: "sec-1",
	})

	// Inject token into cache right before c.mu.Lock() is acquired,
	// triggering the double-check branch deterministically.
	c.beforeWriteLock = func() {
		c.mu.Lock()
		c.tokens["https://api.example.com/res"] = &cachedToken{
			accessToken: "double-checked-token",
			expiresAt:   time.Now().Add(1 * time.Hour),
		}
		c.mu.Unlock()
	}

	token, err := c.GetToken(ctx, "https://api.example.com/res")
	require.NoError(t, err)
	assert.Equal(t, "double-checked-token", token)
}

func TestClient_GetToken_Caching(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	requestCount := 0
	currTime := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/token", r.URL.Path)
		_ = r.ParseForm()
		assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))

		user, pass, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "cid", user)
		assert.Equal(t, "csec", pass)

		requestCount++
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(oauth2.TokenResponse{ //nolint:gosec // false positive for test token response
			AccessToken: "opq_token_" + r.Form.Get("resource"),
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Resource:    r.Form.Get("resource"),
		})
	}))
	defer ts.Close()

	c := New(Config{
		ServerURL:    ts.URL,
		ClientID:     "cid",
		ClientSecret: "csec",
		ExpiryBuffer: 30 * time.Second,
	})
	c.SetNowFunc(func() time.Time { return currTime })

	resA := "https://api.example.com/v1/certs/1"
	resB := "https://api.example.com/v1/certs/2"

	// 1. Initial fetch for resA
	tokA1, err := c.GetToken(ctx, resA)
	require.NoError(t, err)
	assert.Equal(t, "opq_token_"+resA, tokA1)
	assert.Equal(t, 1, requestCount)

	// 2. Cache hit for resA (requestCount should not increase)
	tokA2, err := c.GetToken(ctx, resA)
	require.NoError(t, err)
	assert.Equal(t, tokA1, tokA2)
	assert.Equal(t, 1, requestCount)

	// 3. Different resource resB (should trigger fetch)
	tokB1, err := c.GetToken(ctx, resB)
	require.NoError(t, err)
	assert.Equal(t, "opq_token_"+resB, tokB1)
	assert.Equal(t, 2, requestCount)

	// 4. Advance time past expiry buffer -> should refresh resA
	currTime = currTime.Add(3580 * time.Second) // 3600 - 20s remaining, less than 30s buffer
	tokA3, err := c.GetToken(ctx, resA)
	require.NoError(t, err)
	assert.Equal(t, 3, requestCount)
	assert.Equal(t, "opq_token_"+resA, tokA3)
}

func TestClient_GetToken_Errors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("server error 500", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("server error"))
		}))
		defer ts.Close()

		c := New(Config{ServerURL: ts.URL})
		_, err := c.GetToken(ctx, "res")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 500")
	})

	t.Run("invalid json response", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("bad-json"))
		}))
		defer ts.Close()

		c := New(Config{ServerURL: ts.URL})
		_, err := c.GetToken(ctx, "res")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode token response")
	})

	t.Run("network error", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		ts.Close()

		c := New(Config{ServerURL: ts.URL})
		_, err := c.GetToken(ctx, "res")
		require.Error(t, err)
	})

	t.Run("invalid request url", func(t *testing.T) {
		t.Parallel()
		c := New(Config{ServerURL: "http://[::1]:bad"})
		_, err := c.GetToken(ctx, "res")
		require.Error(t, err)
	})
}

func TestClient_Introspect(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/oauth/introspect", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(oauth2.IntrospectResponse{
				Active:   true,
				ClientID: "cid",
			})
		}))
		defer ts.Close()

		c := New(Config{ServerURL: ts.URL})
		resp, err := c.Introspect(ctx, "opq_token")
		require.NoError(t, err)
		assert.True(t, resp.Active)
		assert.Equal(t, "cid", resp.ClientID)
	})

	t.Run("server error", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		c := New(Config{ServerURL: ts.URL})
		_, err := c.Introspect(ctx, "token")
		require.Error(t, err)
	})

	t.Run("invalid json response", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not-json"))
		}))
		defer ts.Close()

		c := New(Config{ServerURL: ts.URL})
		_, err := c.Introspect(ctx, "token")
		require.Error(t, err)
	})

	t.Run("network error", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		ts.Close()

		c := New(Config{ServerURL: ts.URL})
		_, err := c.Introspect(ctx, "token")
		require.Error(t, err)
	})

	t.Run("invalid request url", func(t *testing.T) {
		t.Parallel()
		c := New(Config{ServerURL: "http://[::1]:bad"})
		_, err := c.Introspect(ctx, "token")
		require.Error(t, err)
	})
}

func TestClient_Revoke(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success and cache eviction", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(oauth2.TokenResponse{ //nolint:gosec // false positive for test token response
					AccessToken: "opq_to_revoke",
					ExpiresIn:   3600,
				})
				return
			}
			assert.Equal(t, "/oauth/revoke", r.URL.Path)
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		c := New(Config{ServerURL: ts.URL})
		// Pre-populate cache
		tok, err := c.GetToken(ctx, "https://api.example.com/v1/certs/1")
		require.NoError(t, err)
		assert.Equal(t, "opq_to_revoke", tok)

		// Revoke
		err = c.Revoke(ctx, tok)
		require.NoError(t, err)

		// Verify cache was cleared
		c.mu.RLock()
		_, exists := c.tokens["https://api.example.com/v1/certs/1"]
		c.mu.RUnlock()
		assert.False(t, exists)
	})

	t.Run("server error", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		c := New(Config{ServerURL: ts.URL})
		err := c.Revoke(ctx, "tok")
		require.Error(t, err)
	})

	t.Run("network error", func(t *testing.T) {
		t.Parallel()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		ts.Close()

		c := New(Config{ServerURL: ts.URL})
		err := c.Revoke(ctx, "tok")
		require.Error(t, err)
	})

	t.Run("invalid request url", func(t *testing.T) {
		t.Parallel()
		c := New(Config{ServerURL: "http://[::1]:bad"})
		err := c.Revoke(ctx, "tok")
		require.Error(t, err)
	})
}

func TestTransport_RoundTrip_And_Do(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	setupTransportTest := func() (*Client, string, *string) {
		var receivedHeader string
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeader = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"cert_id":"cert-001"}`))
		}))

		auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(oauth2.TokenResponse{ //nolint:gosec // false positive for test token response
				AccessToken: "opq_injected_token",
				ExpiresIn:   3600,
			})
		}))

		c := New(Config{
			ServerURL:    auth.URL,
			ClientID:     "cid",
			ClientSecret: "csec",
		})
		return c, target.URL, &receivedHeader
	}

	t.Run("Client.Do with automatic URL resource", func(t *testing.T) {
		t.Parallel()
		c, targetURL, headerPtr := setupTransportTest()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, targetURL+"/v1/certificates/cert-001", nil)
		resp, err := c.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "Bearer opq_injected_token", *headerPtr)
	})

	t.Run("Client.Do with explicit resource override", func(t *testing.T) {
		t.Parallel()
		c, targetURL, headerPtr := setupTransportTest()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, targetURL+"/custom", nil)
		resp, err := c.Do(req, "https://api.example.com/custom/resource")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "Bearer opq_injected_token", *headerPtr)
	})

	t.Run("Client.HTTPClient standard client usage", func(t *testing.T) {
		t.Parallel()
		c, targetURL, _ := setupTransportTest()
		httpClient := c.HTTPClient()
		resp, err := httpClient.Get(targetURL + "/v1/certificates/cert-001")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "cert-001")
	})

	t.Run("token acquisition failure in RoundTrip", func(t *testing.T) {
		t.Parallel()
		badClient := New(Config{ServerURL: "http://localhost:1"}) // No server listening
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:2", nil)
		_, err := badClient.Do(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to acquire token")
	})
}
