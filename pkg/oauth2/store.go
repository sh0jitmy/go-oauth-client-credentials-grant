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
)

// Store defines the storage operations required by the OAuth 2.0 engine.
type Store interface {
	// CreateClient stores a new OAuth 2.0 client.
	CreateClient(ctx context.Context, client *Client) error

	// GetClient retrieves an OAuth 2.0 client by its ID.
	GetClient(ctx context.Context, clientID string) (*Client, error)

	// SaveToken stores an issued OAuth 2.0 token.
	SaveToken(ctx context.Context, token *Token) error

	// GetTokenByHash retrieves an OAuth 2.0 token by its SHA-256 hash.
	GetTokenByHash(ctx context.Context, tokenHash string) (*Token, error)

	// RevokeToken marks an OAuth 2.0 token as revoked.
	RevokeToken(ctx context.Context, tokenHash string) error
}
