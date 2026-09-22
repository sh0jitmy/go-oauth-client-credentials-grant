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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupTestRouter(svc *Service) *gin.Engine {
	r := gin.New()
	RegisterRoutes(r.Group("/oauth"), svc)
	return r
}

func TestHandlers_RegisterClient(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore()
	svc := NewService(store, WithBcryptCost(bcrypt.MinCost))
	r := setupTestRouter(svc)

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		body, _ := json.Marshal(RegisterClientRequest{
			Name:             "Client 1",
			AllowedResources: []string{"https://api.example.com/v1/certs/1"},
		})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/clients", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp RegisterClientResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.ClientID)
		assert.NotEmpty(t, resp.ClientSecret)
		assert.Equal(t, "Client 1", resp.Name)
	})

	t.Run("invalid json", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/clients", strings.NewReader("{invalid-json"))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("validation failure (empty name)", func(t *testing.T) {
		t.Parallel()
		body, _ := json.Marshal(RegisterClientRequest{Name: ""})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/clients", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandlers_TokenHandler(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()
	svc := NewService(store, WithBcryptCost(bcrypt.MinCost))
	r := setupTestRouter(svc)

	reg, err := svc.RegisterClient(ctx, &RegisterClientRequest{
		Name:             "Token Client",
		AllowedResources: []string{"https://api.example.com/v1/certs/1"},
		AllowedScopes:    []string{"cert:read"},
	})
	require.NoError(t, err)

	t.Run("success with JSON and body credentials", func(t *testing.T) {
		t.Parallel()
		body, _ := json.Marshal(TokenRequest{ //nolint:gosec // false positive for test request payload
			GrantType:    "client_credentials",
			ClientID:     reg.ClientID,
			ClientSecret: reg.ClientSecret,
			Resource:     "https://api.example.com/v1/certs/1",
			Scope:        "cert:read",
		})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/token", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		var resp TokenResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
	})

	t.Run("success with urlencoded and basic auth", func(t *testing.T) {
		t.Parallel()
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("resource", "https://api.example.com/v1/certs/1")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(reg.ClientID, reg.ClientSecret)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("invalid json body", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("{invalid"))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid client credentials (401 with WWW-Authenticate)", func(t *testing.T) {
		t.Parallel()
		body, _ := json.Marshal(TokenRequest{ //nolint:gosec // false positive for test request payload
			GrantType:    "client_credentials",
			ClientID:     reg.ClientID,
			ClientSecret: "wrong-secret",
		})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/token", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Header().Get("WWW-Authenticate"), "Basic")
	})

	t.Run("invalid grant type", func(t *testing.T) {
		t.Parallel()
		body, _ := json.Marshal(TokenRequest{ //nolint:gosec // false positive for test request payload
			GrantType:    "password",
			ClientID:     reg.ClientID,
			ClientSecret: reg.ClientSecret,
		})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/token", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_grant")
	})

	t.Run("invalid target / resource mismatch", func(t *testing.T) {
		t.Parallel()
		body, _ := json.Marshal(TokenRequest{ //nolint:gosec // false positive for test request payload
			GrantType:    "client_credentials",
			ClientID:     reg.ClientID,
			ClientSecret: reg.ClientSecret,
			Resource:     "https://api.example.com/v1/certs/999",
		})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/token", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_target")
	})

	t.Run("invalid scope", func(t *testing.T) {
		t.Parallel()
		body, _ := json.Marshal(TokenRequest{ //nolint:gosec // false positive for test request payload
			GrantType:    "client_credentials",
			ClientID:     reg.ClientID,
			ClientSecret: reg.ClientSecret,
			Resource:     "https://api.example.com/v1/certs/1",
			Scope:        "admin:root",
		})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/token", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_scope")
	})

	t.Run("invalid form body", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=%ZZ"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Failed to parse form")
	})

	t.Run("default error branch", func(t *testing.T) {
		t.Parallel()
		m := &mockStore{
			Store:        store,
			saveTokenErr: errors.New("unexpected error"),
		}
		svcErr := NewService(m)
		rErr := setupTestRouter(svcErr)

		body, _ := json.Marshal(TokenRequest{ //nolint:gosec // false positive for test request payload
			GrantType:    "client_credentials",
			ClientID:     reg.ClientID,
			ClientSecret: reg.ClientSecret,
			Resource:     "https://api.example.com/v1/certs/1",
		})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/oauth/token", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rErr.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "failed to store token")
	})
}

func TestHandlers_Introspect_And_Revoke(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()
	svc := NewService(store, WithBcryptCost(bcrypt.MinCost))
	r := setupTestRouter(svc)

	reg, _ := svc.RegisterClient(ctx, &RegisterClientRequest{Name: "Intro Client"})
	tokResp, _ := svc.IssueToken(ctx, &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     reg.ClientID,
		ClientSecret: reg.ClientSecret,
	})

	// Introspect - Form
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader("token="+tokResp.AccessToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"active":true`)

	// Introspect - Query
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/oauth/introspect?token="+tokResp.AccessToken, nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"active":true`)

	// Introspect - JSON body
	body, _ := json.Marshal(map[string]string{"token": tokResp.AccessToken})
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/oauth/introspect", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Introspect - Missing token
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/oauth/introspect", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Revoke - Missing token
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/oauth/revoke", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Revoke - Success
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader("token="+tokResp.AccessToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Introspect after revoke -> active: false
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader("token="+tokResp.AccessToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"active":false`)
}

func TestHandlers_StoreErrorBranches(t *testing.T) {
	t.Parallel()

	// Test store failure in Introspect and Revoke handlers
	m := &mockStore{
		getTokenErr:    errors.New("db error"),
		revokeTokenErr: errors.New("db error"),
	}
	svc := NewService(m)
	r := setupTestRouter(svc)

	// Introspect store error -> 500
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader("token=abc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Revoke store error -> 500
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader("token=abc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
