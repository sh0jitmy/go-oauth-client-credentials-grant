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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	defaultTokenTTL = 3600 * time.Second
	tokenEntropyLen = 32
)

// Service provides OAuth 2.0 Client Credentials and token management logic.
type Service struct {
	store      Store
	telemetry  *Telemetry
	tokenTTL   time.Duration
	bcryptCost int
	randReader io.Reader
	nowFunc    func() time.Time
}

// ServiceOption configures the Service.
type ServiceOption func(*Service)

// WithRandReader overrides the random byte reader.
func WithRandReader(r io.Reader) ServiceOption {
	return func(s *Service) {
		if r != nil {
			s.randReader = r
		}
	}
}

// WithBcryptCost overrides the bcrypt hashing cost.
func WithBcryptCost(cost int) ServiceOption {
	return func(s *Service) {
		if cost > 0 {
			s.bcryptCost = cost
		}
	}
}

// WithTokenTTL sets the lifetime duration for issued tokens.
func WithTokenTTL(d time.Duration) ServiceOption {
	return func(s *Service) {
		if d > 0 {
			s.tokenTTL = d
		}
	}
}

// WithTelemetry sets the telemetry handler.
func WithTelemetry(t *Telemetry) ServiceOption {
	return func(s *Service) {
		if t != nil {
			s.telemetry = t
		}
	}
}

// WithNowFunc overrides the current time provider (for deterministic testing).
func WithNowFunc(fn func() time.Time) ServiceOption {
	return func(s *Service) {
		if fn != nil {
			s.nowFunc = fn
		}
	}
}

// NewService initializes a new OAuth 2.0 Service with the specified store and options.
func NewService(store Store, opts ...ServiceOption) *Service {
	s := &Service{
		store:      store,
		telemetry:  NewTelemetry(),
		tokenTTL:   defaultTokenTTL,
		bcryptCost: bcrypt.DefaultCost,
		randReader: rand.Reader,
		nowFunc:    time.Now,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// RegisterClient registers a new OAuth 2.0 client with hashed credentials.
func (s *Service) RegisterClient(ctx context.Context, req *RegisterClientRequest) (*RegisterClientResponse, error) {
	if req == nil || strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidRequest)
	}

	// Validate all allowed resources are RFC 8707 compliant absolute URIs
	for _, res := range req.AllowedResources {
		if err := ValidateAbsoluteURI(res); err != nil {
			return nil, fmt.Errorf("%w: invalid allowed_resource %q: %v", ErrInvalidTarget, res, err)
		}
	}

	clientID, err := s.generateRandomHex(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client_id: %w", err)
	}

	rawSecret, err := s.generateRandomBase64(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client_secret: %w", err)
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(rawSecret), s.bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash secret: %w", err)
	}

	now := s.nowFunc().UTC()
	client := &Client{
		ID:               clientID,
		SecretHash:       string(hashedSecret),
		Name:             req.Name,
		AllowedResources: req.AllowedResources,
		AllowedScopes:    req.AllowedScopes,
		CreatedAt:        now,
	}

	if err := s.store.CreateClient(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to store client: %w", err)
	}

	return &RegisterClientResponse{
		ClientID:         clientID,
		ClientSecret:     rawSecret,
		Name:             client.Name,
		AllowedResources: client.AllowedResources,
		AllowedScopes:    client.AllowedScopes,
		CreatedAt:        client.CreatedAt,
	}, nil
}

// IssueToken handles the OAuth 2.0 Client Credentials Grant and RFC 8707 Resource Indicators.
func (s *Service) IssueToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	start := s.nowFunc()

	if req == nil {
		s.telemetry.RecordTokenRequest(ctx, "", "invalid_request", "", "", time.Since(start), ErrInvalidRequest)
		return nil, ErrInvalidRequest
	}

	if req.GrantType != "client_credentials" {
		s.telemetry.RecordTokenRequest(ctx, req.GrantType, "invalid_grant", req.ClientID, req.Resource, time.Since(start), ErrInvalidGrant)
		return nil, ErrInvalidGrant
	}

	if req.Resource != "" {
		if err := ValidateAbsoluteURI(req.Resource); err != nil {
			s.telemetry.RecordTokenRequest(ctx, req.GrantType, "invalid_resource", req.ClientID, req.Resource, time.Since(start), err)
			return nil, err
		}
	}

	client, err := s.store.GetClient(ctx, req.ClientID)
	if err != nil {
		s.telemetry.RecordTokenRequest(ctx, req.GrantType, "invalid_client", req.ClientID, req.Resource, time.Since(start), ErrInvalidClient)
		return nil, ErrInvalidClient
	}

	if cmpErr := bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(req.ClientSecret)); cmpErr != nil {
		s.telemetry.RecordTokenRequest(ctx, req.GrantType, "invalid_client", req.ClientID, req.Resource, time.Since(start), ErrInvalidClient)
		return nil, ErrInvalidClient
	}

	// Validate resource authorization (if client has restricted resources)
	if len(client.AllowedResources) > 0 {
		if req.Resource == "" || !containsString(client.AllowedResources, req.Resource) {
			s.telemetry.RecordTokenRequest(ctx, req.GrantType, "unauthorized_resource", req.ClientID, req.Resource, time.Since(start), ErrInvalidTarget)
			return nil, ErrInvalidTarget
		}
	}

	// Validate scope authorization (if client has restricted scopes)
	if len(client.AllowedScopes) > 0 && req.Scope != "" {
		requestedScopes := strings.Fields(req.Scope)
		for _, sc := range requestedScopes {
			if !containsString(client.AllowedScopes, sc) {
				s.telemetry.RecordTokenRequest(ctx, req.GrantType, "unauthorized_scope", req.ClientID, req.Resource, time.Since(start), ErrScopeMismatch)
				return nil, ErrScopeMismatch
			}
		}
	}

	rawToken, err := s.generateRandomBase64(tokenEntropyLen)
	if err != nil {
		s.telemetry.RecordTokenRequest(ctx, req.GrantType, "internal_error", req.ClientID, req.Resource, time.Since(start), err)
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	opaqueToken := "opq_" + rawToken

	tokenHash := ComputeTokenHash(opaqueToken)
	now := s.nowFunc().UTC()
	expiresAt := now.Add(s.tokenTTL)

	token := &Token{
		TokenHash: tokenHash,
		ClientID:  client.ID,
		Resource:  req.Resource,
		Scope:     req.Scope,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	if err := s.store.SaveToken(ctx, token); err != nil {
		s.telemetry.RecordTokenRequest(ctx, req.GrantType, "internal_error", req.ClientID, req.Resource, time.Since(start), err)
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	s.telemetry.RecordTokenRequest(ctx, req.GrantType, "ok", req.ClientID, req.Resource, time.Since(start), nil)

	return &TokenResponse{
		AccessToken: opaqueToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.tokenTTL.Seconds()),
		Resource:    req.Resource,
		Scope:       req.Scope,
	}, nil
}

// ValidateToken verifies the provided Opaque Token against the store and expiry/revocation rules.
func (s *Service) ValidateToken(ctx context.Context, rawToken string) (*Token, error) {
	if rawToken == "" {
		return nil, ErrInvalidRequest
	}

	tokenHash := ComputeTokenHash(rawToken)
	token, err := s.store.GetTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return nil, ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to retrieve token: %w", err)
	}

	now := s.nowFunc().UTC()
	if token.IsRevoked() {
		return nil, ErrTokenRevoked
	}
	if token.IsExpired(now) {
		return nil, ErrTokenExpired
	}

	return token, nil
}

// IntrospectToken handles RFC 7662 token introspection.
func (s *Service) IntrospectToken(ctx context.Context, rawToken string) (*IntrospectResponse, error) {
	token, err := s.ValidateToken(ctx, rawToken)
	if err != nil {
		// RFC 7662: Inactive or invalid tokens must return { active: false }
		if errors.Is(err, ErrTokenNotFound) || errors.Is(err, ErrTokenExpired) || errors.Is(err, ErrTokenRevoked) || errors.Is(err, ErrInvalidRequest) {
			return &IntrospectResponse{Active: false}, nil
		}
		return nil, err
	}

	return &IntrospectResponse{
		Active:    true,
		ClientID:  token.ClientID,
		Resource:  token.Resource,
		Scope:     token.Scope,
		Exp:       token.ExpiresAt.Unix(),
		TokenType: "Bearer",
	}, nil
}

// RevokeToken handles RFC 7009 token revocation.
func (s *Service) RevokeToken(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return nil
	}

	tokenHash := ComputeTokenHash(rawToken)
	err := s.store.RevokeToken(ctx, tokenHash)
	if err != nil && !errors.Is(err, ErrTokenNotFound) {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	return nil
}

// ComputeTokenHash computes the SHA-256 hex string of a raw token.
func ComputeTokenHash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

func (s *Service) generateRandomHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := io.ReadFull(s.randReader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Service) generateRandomBase64(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := io.ReadFull(s.randReader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
