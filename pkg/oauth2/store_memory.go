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
	"fmt"
	"sync"
	"time"
)

var _ Store = (*MemoryStore)(nil)

// MemoryStore is an in-memory, thread-safe implementation of Store.
type MemoryStore struct {
	mu      sync.RWMutex
	clients map[string]*Client
	tokens  map[string]*Token
}

// NewMemoryStore creates and initializes a new MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients: make(map[string]*Client),
		tokens:  make(map[string]*Token),
	}
}

// CreateClient stores a client in memory.
func (m *MemoryStore) CreateClient(_ context.Context, client *Client) error {
	if client == nil || client.ID == "" {
		return fmt.Errorf("%w: invalid client", ErrInvalidRequest)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.clients[client.ID]; exists {
		return fmt.Errorf("%w: client already exists", ErrInvalidRequest)
	}

	// Defensive copy
	c := *client
	c.AllowedResources = append([]string(nil), client.AllowedResources...)
	c.AllowedScopes = append([]string(nil), client.AllowedScopes...)
	m.clients[client.ID] = &c
	return nil
}

// GetClient retrieves a client from memory by ID.
func (m *MemoryStore) GetClient(_ context.Context, clientID string) (*Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	client, exists := m.clients[clientID]
	if !exists {
		return nil, ErrInvalidClient
	}

	// Defensive copy
	c := *client
	c.AllowedResources = append([]string(nil), client.AllowedResources...)
	c.AllowedScopes = append([]string(nil), client.AllowedScopes...)
	return &c, nil
}

// SaveToken stores a token in memory indexed by token hash.
func (m *MemoryStore) SaveToken(_ context.Context, token *Token) error {
	if token == nil || token.TokenHash == "" {
		return fmt.Errorf("%w: invalid token", ErrInvalidRequest)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	t := *token
	m.tokens[token.TokenHash] = &t
	return nil
}

// GetTokenByHash retrieves a token by its SHA-256 hash.
func (m *MemoryStore) GetTokenByHash(_ context.Context, tokenHash string) (*Token, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	token, exists := m.tokens[tokenHash]
	if !exists {
		return nil, ErrTokenNotFound
	}

	t := *token
	return &t, nil
}

// RevokeToken marks a token as revoked.
func (m *MemoryStore) RevokeToken(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	token, exists := m.tokens[tokenHash]
	if !exists {
		return ErrTokenNotFound
	}

	now := time.Now().UTC()
	token.RevokedAt = &now
	return nil
}
