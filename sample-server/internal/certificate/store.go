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

package certificate

import (
	"context"
	"errors"
	"sync"
)

var (
	// ErrCertificateNotFound indicates certificate does not exist.
	ErrCertificateNotFound = errors.New("certificate not found")
	// ErrChallengeNotFound indicates challenge token does not exist.
	ErrChallengeNotFound = errors.New("challenge not found")
)

// Store defines persistence operations for certificates and challenges.
type Store interface {
	GetCertificate(ctx context.Context, id string) (*Certificate, error)
	SaveCertificate(ctx context.Context, cert *Certificate) error
	GetChallenge(ctx context.Context, token string) (*HTTP01Challenge, error)
	SaveChallenge(ctx context.Context, ch *HTTP01Challenge) error
	DeleteChallenge(ctx context.Context, token string) error
}

// MemoryStore provides in-memory thread-safe implementation of Store.
type MemoryStore struct {
	mu           sync.RWMutex
	certificates map[string]*Certificate
	challenges   map[string]*HTTP01Challenge
}

// NewMemoryStore initializes a new MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		certificates: make(map[string]*Certificate),
		challenges:   make(map[string]*HTTP01Challenge),
	}
}

// GetCertificate returns certificate by ID.
func (s *MemoryStore) GetCertificate(_ context.Context, id string) (*Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, ok := s.certificates[id]
	if !ok {
		return nil, ErrCertificateNotFound
	}
	cp := *cert
	return &cp, nil
}

// SaveCertificate creates or updates a certificate.
func (s *MemoryStore) SaveCertificate(_ context.Context, cert *Certificate) error {
	if cert == nil {
		return errors.New("certificate cannot be nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *cert
	s.certificates[cert.ID] = &cp
	return nil
}

// GetChallenge returns challenge by token.
func (s *MemoryStore) GetChallenge(_ context.Context, token string) (*HTTP01Challenge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ch, ok := s.challenges[token]
	if !ok {
		return nil, ErrChallengeNotFound
	}
	cp := *ch
	return &cp, nil
}

// SaveChallenge records an ACME challenge.
func (s *MemoryStore) SaveChallenge(_ context.Context, ch *HTTP01Challenge) error {
	if ch == nil {
		return errors.New("challenge cannot be nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *ch
	s.challenges[ch.Token] = &cp
	return nil
}

// DeleteChallenge removes an ACME challenge after completion.
func (s *MemoryStore) DeleteChallenge(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.challenges[token]; !ok {
		return ErrChallengeNotFound
	}
	delete(s.challenges, token)
	return nil
}
