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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestMiddleware_TokenAuth(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	currTime := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)

	setupRouter := func(now time.Time) (*gin.Engine, *Service, string, string) {
		store := NewMemoryStore()
		svc := NewService(store, WithNowFunc(func() time.Time { return now }), WithBcryptCost(bcrypt.MinCost))
		reg, _ := svc.RegisterClient(ctx, &RegisterClientRequest{Name: "MW Test"})
		tokResp, _ := svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     reg.ClientID,
			ClientSecret: reg.ClientSecret,
			Resource:     "https://api.example.com/v1/certs/1",
			Scope:        "cert:read",
		})

		r := gin.New()
		r.Use(TokenAuthMiddleware(svc))
		r.GET("/protected", func(c *gin.Context) {
			tok, ok := GetTokenFromContext(c)
			if !ok || tok == nil {
				c.Status(http.StatusInternalServerError)
				return
			}
			c.JSON(http.StatusOK, gin.H{"client_id": tok.ClientID})
		})
		return r, svc, tokResp.AccessToken, reg.ClientID
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		r, _, token, clientID := setupRouter(currTime)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), clientID)
	})

	t.Run("missing authorization header", func(t *testing.T) {
		t.Parallel()
		r, _, _, _ := setupRouter(currTime)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Header().Get("WWW-Authenticate"), "invalid_request")
	})

	t.Run("malformed authorization header", func(t *testing.T) {
		t.Parallel()
		r, _, _, _ := setupRouter(currTime)
		malformed := []string{"Basic abc", "Bearer", "Token 123", "Bearer   "}
		for _, header := range malformed {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", header)
			r.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Contains(t, w.Header().Get("WWW-Authenticate"), "invalid_token")
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		t.Parallel()
		r, _, _, _ := setupRouter(currTime)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid token")
	})

	t.Run("expired token", func(t *testing.T) {
		t.Parallel()
		testTime := currTime
		store := NewMemoryStore()
		svc := NewService(store, WithNowFunc(func() time.Time { return testTime }), WithBcryptCost(bcrypt.MinCost))
		reg, _ := svc.RegisterClient(ctx, &RegisterClientRequest{Name: "MW Test"})
		tokResp, _ := svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     reg.ClientID,
			ClientSecret: reg.ClientSecret,
			Resource:     "https://api.example.com/v1/certs/1",
		})

		r := gin.New()
		r.Use(TokenAuthMiddleware(svc))
		r.GET("/protected", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		// Advance clock by 2 hours so token is expired
		testTime = currTime.Add(2 * time.Hour)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Token has expired")
	})

	t.Run("revoked token", func(t *testing.T) {
		t.Parallel()
		r, svc, token, _ := setupRouter(currTime)
		err := svc.RevokeToken(ctx, token)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Token has been revoked")
	})
}

func TestMiddleware_RequireResource(t *testing.T) {
	t.Parallel()

	r := gin.New()
	r.GET("/api/:id",
		func(c *gin.Context) {
			// Simulate injected token
			res := c.Query("token_res")
			if c.Query("no_token") != "true" {
				c.Set(TokenContextKey, &Token{Resource: res})
			}
			c.Next()
		},
		RequireResource(func(c *gin.Context) string {
			return "https://api.example.com/v1/certs/" + c.Param("id")
		}),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	t.Run("resource match", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/cert-1?token_res=https://api.example.com/v1/certs/cert-1", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("resource mismatch (403)", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/cert-1?token_res=https://api.example.com/v1/certs/cert-2", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("unrestricted token (empty resource passes through)", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/cert-1?token_res=", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("missing token in context (401)", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/cert-1?no_token=true", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestMiddleware_RequireScope(t *testing.T) {
	t.Parallel()

	r := gin.New()
	r.GET("/api/scoped",
		func(c *gin.Context) {
			sc := c.Query("token_scope")
			if c.Query("no_token") != "true" {
				c.Set(TokenContextKey, &Token{Scope: sc})
			}
			c.Next()
		},
		RequireScope("admin:write"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	t.Run("scope matches", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/scoped?token_scope=read admin:write delete", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("scope missing (403)", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/scoped?token_scope=read write", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("empty token scope (passes through)", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/scoped?token_scope=", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("missing token in context (401)", func(t *testing.T) {
		t.Parallel()
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/scoped?no_token=true", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
