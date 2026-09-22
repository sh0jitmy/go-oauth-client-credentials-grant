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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_ClientOperations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()

	// Invalid client creation
	err := store.CreateClient(ctx, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidRequest)

	err = store.CreateClient(ctx, &Client{ID: ""})
	require.Error(t, err)

	// Valid creation
	client := &Client{
		ID:               "client-123",
		SecretHash:       "hash-abc",
		Name:             "Service A",
		AllowedResources: []string{"https://api.example.com/v1/certs/1"},
		AllowedScopes:    []string{"read", "write"},
		CreatedAt:        time.Now().UTC(),
	}
	err = store.CreateClient(ctx, client)
	require.NoError(t, err)

	// Duplicate client creation
	err = store.CreateClient(ctx, client)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidRequest)

	// Get client success
	retrieved, err := store.GetClient(ctx, "client-123")
	require.NoError(t, err)
	assert.Equal(t, "client-123", retrieved.ID)
	assert.Equal(t, "Service A", retrieved.Name)
	assert.Equal(t, []string{"https://api.example.com/v1/certs/1"}, retrieved.AllowedResources)
	assert.Equal(t, []string{"read", "write"}, retrieved.AllowedScopes)

	// Get client not found
	_, err = store.GetClient(ctx, "non-existent")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidClient)
}

func TestMemoryStore_TokenOperations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryStore()

	// Invalid token creation
	err := store.SaveToken(ctx, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidRequest)

	err = store.SaveToken(ctx, &Token{TokenHash: ""})
	require.Error(t, err)

	// Valid token creation
	tok := &Token{
		TokenHash: "hash-token-1",
		ClientID:  "client-123",
		Resource:  "https://api.example.com/v1/certs/1",
		Scope:     "read",
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	err = store.SaveToken(ctx, tok)
	require.NoError(t, err)

	// Get token success
	retrieved, err := store.GetTokenByHash(ctx, "hash-token-1")
	require.NoError(t, err)
	assert.Equal(t, "client-123", retrieved.ClientID)
	assert.Equal(t, "hash-token-1", retrieved.TokenHash)
	assert.Nil(t, retrieved.RevokedAt)

	// Get token not found
	_, err = store.GetTokenByHash(ctx, "non-existent")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrTokenNotFound)

	// Revoke token success
	err = store.RevokeToken(ctx, "hash-token-1")
	require.NoError(t, err)

	revoked, err := store.GetTokenByHash(ctx, "hash-token-1")
	require.NoError(t, err)
	assert.NotNil(t, revoked.RevokedAt)

	// Revoke token not found
	err = store.RevokeToken(ctx, "non-existent")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrTokenNotFound)
}
