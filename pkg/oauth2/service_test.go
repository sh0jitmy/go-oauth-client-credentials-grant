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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type errReader struct{}

func (e *errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("read failed")
}

type stepErrReader struct {
	count   int
	errStep int
}

func (s *stepErrReader) Read(p []byte) (n int, err error) {
	s.count++
	if s.count == s.errStep {
		return 0, errors.New("step read failed")
	}
	for i := range p {
		p[i] = byte(i)
	}
	return len(p), nil
}

// mockStore is a test helper to simulate arbitrary store errors.
type mockStore struct {
	Store
	createClientErr error
	getClientErr    error
	clientRet       *Client
	saveTokenErr    error
	getTokenErr     error
	tokenRet        *Token
	revokeTokenErr  error
}

func (m *mockStore) CreateClient(ctx context.Context, c *Client) error {
	if m.createClientErr != nil {
		return m.createClientErr
	}
	if m.Store != nil {
		return m.Store.CreateClient(ctx, c)
	}
	return nil
}

func (m *mockStore) GetClient(ctx context.Context, id string) (*Client, error) {
	if m.getClientErr != nil {
		return nil, m.getClientErr
	}
	if m.clientRet != nil {
		return m.clientRet, nil
	}
	if m.Store != nil {
		return m.Store.GetClient(ctx, id)
	}
	return nil, ErrInvalidClient
}

func (m *mockStore) SaveToken(ctx context.Context, t *Token) error {
	if m.saveTokenErr != nil {
		return m.saveTokenErr
	}
	if m.Store != nil {
		return m.Store.SaveToken(ctx, t)
	}
	return nil
}

func (m *mockStore) GetTokenByHash(ctx context.Context, h string) (*Token, error) {
	if m.getTokenErr != nil {
		return nil, m.getTokenErr
	}
	if m.tokenRet != nil {
		return m.tokenRet, nil
	}
	if m.Store != nil {
		return m.Store.GetTokenByHash(ctx, h)
	}
	return nil, ErrTokenNotFound
}

func (m *mockStore) RevokeToken(ctx context.Context, h string) error {
	if m.revokeTokenErr != nil {
		return m.revokeTokenErr
	}
	if m.Store != nil {
		return m.Store.RevokeToken(ctx, h)
	}
	return nil
}

func TestService_Options(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	telem := NewTelemetry()
	fixedTime := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)

	svc := NewService(store,
		WithTokenTTL(1800*time.Second),
		WithTelemetry(telem),
		WithNowFunc(func() time.Time { return fixedTime }),
	)

	assert.Equal(t, 1800*time.Second, svc.tokenTTL)
	assert.Equal(t, fixedTime, svc.nowFunc())

	// Test nil guards in options
	svc2 := NewService(store,
		WithTokenTTL(-1),
		WithTelemetry(nil),
		WithNowFunc(nil),
	)
	assert.Equal(t, defaultTokenTTL, svc2.tokenTTL)
}

func TestService_RegisterClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success with allowed resources and scopes", func(t *testing.T) {
		t.Parallel()
		store := NewMemoryStore()
		svc := NewService(store)

		req := &RegisterClientRequest{
			Name: "Order Service",
			AllowedResources: []string{
				"https://api.example.com/v1/certificates/cert-001",
			},
			AllowedScopes: []string{"read", "write"},
		}

		resp, err := svc.RegisterClient(ctx, req)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.ClientID)
		assert.NotEmpty(t, resp.ClientSecret)
		assert.Equal(t, "Order Service", resp.Name)
		assert.Equal(t, req.AllowedResources, resp.AllowedResources)
		assert.Equal(t, req.AllowedScopes, resp.AllowedScopes)

		// Verify stored client
		stored, err := store.GetClient(ctx, resp.ClientID)
		require.NoError(t, err)
		assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored.SecretHash), []byte(resp.ClientSecret)))
	})

	t.Run("nil request", func(t *testing.T) {
		t.Parallel()
		svc := NewService(NewMemoryStore())
		_, err := svc.RegisterClient(ctx, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidRequest)
	})

	t.Run("empty name", func(t *testing.T) {
		t.Parallel()
		svc := NewService(NewMemoryStore())
		_, err := svc.RegisterClient(ctx, &RegisterClientRequest{Name: "   "})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidRequest)
	})

	t.Run("invalid allowed resource URI", func(t *testing.T) {
		t.Parallel()
		svc := NewService(NewMemoryStore())
		req := &RegisterClientRequest{
			Name:             "Bad Client",
			AllowedResources: []string{"relative/uri"},
		}
		_, err := svc.RegisterClient(ctx, req)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidTarget)
	})

	t.Run("random generator errors", func(t *testing.T) {
		t.Parallel()
		// Error on first read (generateRandomHex)
		svcErr1 := NewService(NewMemoryStore(), WithRandReader(&errReader{}), WithBcryptCost(bcrypt.MinCost))
		_, err := svcErr1.RegisterClient(ctx, &RegisterClientRequest{Name: "Client"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to generate client_id")

		// Error on second read (generateRandomBase64)
		svcErr2 := NewService(NewMemoryStore(), WithRandReader(&stepErrReader{errStep: 2}), WithBcryptCost(bcrypt.MinCost))
		_, err = svcErr2.RegisterClient(ctx, &RegisterClientRequest{Name: "Client"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to generate client_secret")

		// Error on bcrypt hashing (invalid cost)
		svcCostErr := NewService(NewMemoryStore(), WithBcryptCost(99))
		_, err = svcCostErr.RegisterClient(ctx, &RegisterClientRequest{Name: "Client"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to hash secret")
	})

	t.Run("store error", func(t *testing.T) {
		t.Parallel()
		m := &mockStore{createClientErr: errors.New("db down")}
		svc := NewService(m)
		_, err := svc.RegisterClient(ctx, &RegisterClientRequest{Name: "Client A"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to store client")
	})
}

func TestService_IssueToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	validTime := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	validResource := "https://api.example.com/v1/certificates/cert-001"

	setupService := func() (*Service, string, string) {
		store := NewMemoryStore()
		svc := NewService(store, WithNowFunc(func() time.Time { return validTime }), WithBcryptCost(bcrypt.MinCost))
		reg, err := svc.RegisterClient(ctx, &RegisterClientRequest{
			Name:             "Cert Manager",
			AllowedResources: []string{validResource},
			AllowedScopes:    []string{"cert:read", "cert:write"},
		})
		if err != nil {
			panic(err)
		}
		return svc, reg.ClientID, reg.ClientSecret
	}

	t.Run("success issue token", func(t *testing.T) {
		t.Parallel()
		svc, clientID, clientSecret := setupService()
		resp, err := svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Resource:     validResource,
			Scope:        "cert:read",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, int64(3600), resp.ExpiresIn)
		assert.Equal(t, validResource, resp.Resource)
		assert.Equal(t, "cert:read", resp.Scope)
	})

	t.Run("nil request", func(t *testing.T) {
		t.Parallel()
		svc, _, _ := setupService()
		_, err := svc.IssueToken(ctx, nil)
		require.ErrorIs(t, err, ErrInvalidRequest)
	})

	t.Run("invalid grant type", func(t *testing.T) {
		t.Parallel()
		svc, clientID, clientSecret := setupService()
		_, err := svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "authorization_code",
			ClientID:     clientID,
			ClientSecret: clientSecret,
		})
		require.ErrorIs(t, err, ErrInvalidGrant)
	})

	t.Run("invalid resource URI", func(t *testing.T) {
		t.Parallel()
		svc, clientID, clientSecret := setupService()
		_, err := svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Resource:     "invalid-relative-uri",
		})
		require.ErrorIs(t, err, ErrInvalidTarget)
	})

	t.Run("client not found", func(t *testing.T) {
		t.Parallel()
		svc, _, clientSecret := setupService()
		_, err := svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     "unknown-client",
			ClientSecret: clientSecret,
		})
		require.ErrorIs(t, err, ErrInvalidClient)
	})

	t.Run("invalid client secret", func(t *testing.T) {
		t.Parallel()
		svc, clientID, _ := setupService()
		_, err := svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     clientID,
			ClientSecret: "wrong-secret",
		})
		require.ErrorIs(t, err, ErrInvalidClient)
	})

	t.Run("unauthorized resource", func(t *testing.T) {
		t.Parallel()
		svc, clientID, clientSecret := setupService()
		_, err := svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Resource:     "https://api.example.com/v1/certificates/unauthorized",
		})
		require.ErrorIs(t, err, ErrInvalidTarget)

		// Empty resource when client requires specific resources
		_, err = svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Resource:     "",
		})
		require.ErrorIs(t, err, ErrInvalidTarget)
	})

	t.Run("unauthorized scope", func(t *testing.T) {
		t.Parallel()
		svc, clientID, clientSecret := setupService()
		_, err := svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Resource:     validResource,
			Scope:        "admin:all",
		})
		require.ErrorIs(t, err, ErrScopeMismatch)
	})

	t.Run("random generator error on token generation", func(t *testing.T) {
		t.Parallel()
		svc, clientID, clientSecret := setupService()
		svc.randReader = &errReader{}

		_, err := svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Resource:     validResource,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to generate token")
	})

	t.Run("store error on save token", func(t *testing.T) {
		t.Parallel()
		store := NewMemoryStore()
		hash, _ := bcrypt.GenerateFromPassword([]byte("sec"), bcrypt.MinCost)
		_ = store.CreateClient(ctx, &Client{ID: "c1", SecretHash: string(hash)})

		m := &mockStore{
			Store:        store,
			saveTokenErr: errors.New("db error"),
		}
		svc := NewService(m)
		_, err := svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     "c1",
			ClientSecret: "sec",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to store token")
	})
}

func TestService_ValidateToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	currTime := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

	setup := func() (*Service, string) {
		store := NewMemoryStore()
		svc := NewService(store, WithNowFunc(func() time.Time { return currTime }))
		reg, _ := svc.RegisterClient(ctx, &RegisterClientRequest{Name: "Test"})
		tokResp, _ := svc.IssueToken(ctx, &TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     reg.ClientID,
			ClientSecret: reg.ClientSecret,
		})
		return svc, tokResp.AccessToken
	}

	t.Run("valid token", func(t *testing.T) {
		t.Parallel()
		svc, token := setup()
		tok, err := svc.ValidateToken(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, ComputeTokenHash(token), tok.TokenHash)
	})

	t.Run("empty token", func(t *testing.T) {
		t.Parallel()
		svc, _ := setup()
		_, err := svc.ValidateToken(ctx, "")
		require.ErrorIs(t, err, ErrInvalidRequest)
	})

	t.Run("token not found", func(t *testing.T) {
		t.Parallel()
		svc, _ := setup()
		_, err := svc.ValidateToken(ctx, "opq_non_existent")
		require.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("token expired", func(t *testing.T) {
		t.Parallel()
		svc, token := setup()
		// Fast forward 2 hours
		svc.nowFunc = func() time.Time { return currTime.Add(2 * time.Hour) }
		_, err := svc.ValidateToken(ctx, token)
		require.ErrorIs(t, err, ErrTokenExpired)
	})

	t.Run("token revoked", func(t *testing.T) {
		t.Parallel()
		svc, token := setup()
		err := svc.RevokeToken(ctx, token)
		require.NoError(t, err)

		_, err = svc.ValidateToken(ctx, token)
		require.ErrorIs(t, err, ErrTokenRevoked)
	})

	t.Run("store error on get token", func(t *testing.T) {
		t.Parallel()
		m := &mockStore{getTokenErr: errors.New("db disk failure")}
		svc := NewService(m)
		_, err := svc.ValidateToken(ctx, "opq_some_token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to retrieve token")
	})
}

func TestService_IntrospectToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store := NewMemoryStore()
	svc := NewService(store)

	reg, _ := svc.RegisterClient(ctx, &RegisterClientRequest{Name: "Test"})
	tokResp, _ := svc.IssueToken(ctx, &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     reg.ClientID,
		ClientSecret: reg.ClientSecret,
		Resource:     "https://api.example.com/v1/certs/1",
	})

	// Valid token
	intro, err := svc.IntrospectToken(ctx, tokResp.AccessToken)
	require.NoError(t, err)
	assert.True(t, intro.Active)
	assert.Equal(t, reg.ClientID, intro.ClientID)
	assert.Equal(t, "https://api.example.com/v1/certs/1", intro.Resource)

	// Invalid token
	introBad, err := svc.IntrospectToken(ctx, "invalid_token")
	require.NoError(t, err)
	assert.False(t, introBad.Active)
}

func TestService_RevokeToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store := NewMemoryStore()
	svc := NewService(store)

	// Empty token revoke does nothing
	err := svc.RevokeToken(ctx, "")
	require.NoError(t, err)

	// Revoke non-existent token succeeds silently (RFC 7009)
	err = svc.RevokeToken(ctx, "opq_not_found")
	require.NoError(t, err)

	// Store error on revoke
	m := &mockStore{revokeTokenErr: errors.New("db lock")}
	svcErr := NewService(m)
	err = svcErr.RevokeToken(ctx, "opq_token")
	require.Error(t, err)
}
