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
	"errors"
	"fmt"
	"net/url"
	"time"
)

var (
	// ErrInvalidRequest indicates a malformed or missing parameter.
	ErrInvalidRequest = errors.New("invalid_request")
	// ErrInvalidClient indicates client authentication failed.
	ErrInvalidClient = errors.New("invalid_client")
	// ErrInvalidGrant indicates an unsupported or invalid grant type.
	ErrInvalidGrant = errors.New("invalid_grant")
	// ErrInvalidTarget indicates an invalid or unauthorized resource target (RFC 8707).
	ErrInvalidTarget = errors.New("invalid_target")
	// ErrUnauthorizedClient indicates the client is not authorized to request this token.
	ErrUnauthorizedClient = errors.New("unauthorized_client")
	// ErrTokenNotFound indicates the token was not found.
	ErrTokenNotFound = errors.New("token_not_found")
	// ErrTokenExpired indicates the token has expired.
	ErrTokenExpired = errors.New("token_expired")
	// ErrTokenRevoked indicates the token was revoked.
	ErrTokenRevoked = errors.New("token_revoked")
	// ErrResourceMismatch indicates the request resource does not match the token resource.
	ErrResourceMismatch = errors.New("resource_mismatch")
	// ErrScopeMismatch indicates the required scope is missing.
	ErrScopeMismatch = errors.New("scope_mismatch")
)

// Client represents an registered OAuth 2.0 client.
type Client struct {
	ID               string    `json:"client_id"`
	SecretHash       string    `json:"-"`
	Name             string    `json:"name"`
	AllowedResources []string  `json:"allowed_resources"`
	AllowedScopes    []string  `json:"allowed_scopes"`
	CreatedAt        time.Time `json:"created_at"`
}

// Token represents an issued OAuth 2.0 Opaque Token.
type Token struct {
	TokenHash string     `json:"token_hash"`
	ClientID  string     `json:"client_id"`
	Resource  string     `json:"resource"`
	Scope     string     `json:"scope"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// IsExpired checks if the token is past its expiration time.
func (t *Token) IsExpired(now time.Time) bool {
	return now.After(t.ExpiresAt)
}

// IsRevoked checks if the token has been revoked.
func (t *Token) IsRevoked() bool {
	return t.RevokedAt != nil
}

// RegisterClientRequest contains parameters for client registration.
type RegisterClientRequest struct {
	Name             string   `json:"name"`
	AllowedResources []string `json:"allowed_resources"`
	AllowedScopes    []string `json:"allowed_scopes"`
}

// RegisterClientResponse contains credentials returned upon successful registration.
type RegisterClientResponse struct {
	ClientID         string    `json:"client_id"`
	ClientSecret     string    `json:"client_secret"`
	Name             string    `json:"name"`
	AllowedResources []string  `json:"allowed_resources"`
	AllowedScopes    []string  `json:"allowed_scopes"`
	CreatedAt        time.Time `json:"created_at"`
}

// TokenRequest represents parameters for token issuance.
type TokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	ClientID     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
	Resource     string `json:"resource" form:"resource"`
	Scope        string `json:"scope" form:"scope"`
}

// TokenResponse represents RFC 6749 Section 5.1 successful token response with RFC 8707 resource.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Resource    string `json:"resource,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

// IntrospectResponse represents RFC 7662 token introspection response.
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	ClientID  string `json:"client_id,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// ValidateAbsoluteURI validates whether a string is an absolute URI without fragment (RFC 8707 & RFC 3986).
func ValidateAbsoluteURI(rawURI string) error {
	if rawURI == "" {
		return fmt.Errorf("%w: resource URI cannot be empty", ErrInvalidTarget)
	}
	u, err := url.Parse(rawURI)
	if err != nil {
		return fmt.Errorf("%w: failed to parse URI: %v", ErrInvalidTarget, err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("%w: URI must be absolute (scheme required)", ErrInvalidTarget)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%w: URI must not contain a fragment component", ErrInvalidTarget)
	}
	return nil
}
