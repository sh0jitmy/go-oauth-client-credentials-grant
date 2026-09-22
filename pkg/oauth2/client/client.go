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

// Package client provides an OAuth 2.0 Client Credentials client with automatic
// in-memory token caching and RFC 8707 Resource Indicators support.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shjtmy/go-oauth-client-credentials-grant/pkg/oauth2"
)

const (
	tokenExpiryBuffer = 30 * time.Second
)

// Config holds OAuth 2.0 client configuration.
type Config struct {
	ServerURL    string        // Base URL of authorization server (e.g. "http://localhost:8080")
	ClientID     string        // Client ID
	ClientSecret string        // Client Secret
	HTTPClient   *http.Client  // Underlying HTTP client (defaults to http.DefaultClient)
	ExpiryBuffer time.Duration // Time buffer before actual expiry to refresh token
}

// cachedToken holds a cached Opaque Token with its local expiration timestamp.
type cachedToken struct {
	accessToken string
	expiresAt   time.Time
}

// Client is an OAuth 2.0 client managing token acquisition and caching.
type Client struct {
	config       Config
	httpClient   *http.Client
	expiryBuffer time.Duration
	nowFunc      func() time.Time

	mu              sync.RWMutex
	tokens          map[string]*cachedToken // Keyed by resource URI (or "" for default)
	jsonMarshal     func(v any) ([]byte, error)
	beforeWriteLock func() // For deterministic testing of double-checked locking
}

// New creates and initializes a new Client.
func New(cfg Config) *Client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	buffer := cfg.ExpiryBuffer
	if buffer <= 0 {
		buffer = tokenExpiryBuffer
	}

	return &Client{
		config:       cfg,
		httpClient:   httpClient,
		expiryBuffer: buffer,
		nowFunc:      time.Now,
		tokens:       make(map[string]*cachedToken),
		jsonMarshal:  json.Marshal,
	}
}

// SetNowFunc allows overriding time.Now for deterministic testing.
func (c *Client) SetNowFunc(fn func() time.Time) {
	if fn != nil {
		c.nowFunc = fn
	}
}

// RegisterClient registers a new OAuth client on the authorization server.
func (c *Client) RegisterClient(ctx context.Context, req *oauth2.RegisterClientRequest) (*oauth2.RegisterClientResponse, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}

	endpoint := strings.TrimRight(c.config.ServerURL, "/") + "/oauth/clients"
	bodyBytes, err := c.jsonMarshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal register request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call register endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("register client failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var regResp oauth2.RegisterClientResponse
	if err := json.Unmarshal(respBody, &regResp); err != nil {
		return nil, fmt.Errorf("failed to decode register response: %w", err)
	}

	return &regResp, nil
}

// GetToken returns a valid Opaque Token for the specified resource.
// If a non-expired cached token exists, it is returned; otherwise a new token is fetched.
func (c *Client) GetToken(ctx context.Context, resourceURI string) (string, error) {
	now := c.nowFunc().UTC()

	// Check in-memory cache
	c.mu.RLock()
	cached, exists := c.tokens[resourceURI]
	if exists && cached.expiresAt.Sub(now) > c.expiryBuffer {
		token := cached.accessToken
		c.mu.RUnlock()
		return token, nil
	}
	c.mu.RUnlock()

	if c.beforeWriteLock != nil {
		c.beforeWriteLock()
	}

	// Cache miss or expired: fetch new token under write lock
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check after acquiring write lock
	if cached, exists := c.tokens[resourceURI]; exists && cached.expiresAt.Sub(now) > c.expiryBuffer {
		return cached.accessToken, nil
	}

	tokenResp, err := c.fetchToken(ctx, resourceURI)
	if err != nil {
		return "", err
	}

	expiresAt := now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	c.tokens[resourceURI] = &cachedToken{
		accessToken: tokenResp.AccessToken,
		expiresAt:   expiresAt,
	}

	return tokenResp.AccessToken, nil
}

// fetchToken executes the HTTP call to /oauth/token.
func (c *Client) fetchToken(ctx context.Context, resourceURI string) (*oauth2.TokenResponse, error) {
	endpoint := strings.TrimRight(c.config.ServerURL, "/") + "/oauth/token"

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	if resourceURI != "" {
		data.Set("resource", resourceURI)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to request token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp oauth2.TokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// Introspect sends a token introspection request to the authorization server.
func (c *Client) Introspect(ctx context.Context, token string) (*oauth2.IntrospectResponse, error) {
	endpoint := strings.TrimRight(c.config.ServerURL, "/") + "/oauth/introspect"

	data := url.Values{}
	data.Set("token", token)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspect request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call introspect endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspect request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var introResp oauth2.IntrospectResponse
	if err := json.Unmarshal(respBody, &introResp); err != nil {
		return nil, fmt.Errorf("failed to decode introspect response: %w", err)
	}

	return &introResp, nil
}

// Revoke sends a token revocation request to the authorization server.
func (c *Client) Revoke(ctx context.Context, token string) error {
	endpoint := strings.TrimRight(c.config.ServerURL, "/") + "/oauth/revoke"

	data := url.Values{}
	data.Set("token", token)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.SetBasicAuth(c.config.ClientID, c.config.ClientSecret)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to call revoke endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoke request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	// Invalidate local cache if this token was cached
	c.mu.Lock()
	for res, cached := range c.tokens {
		if cached.accessToken == token {
			delete(c.tokens, res)
		}
	}
	c.mu.Unlock()

	return nil
}
