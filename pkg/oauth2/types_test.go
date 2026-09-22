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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAbsoluteURI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		uri     string
		wantErr bool
		errIs   error
	}{
		{
			name:    "valid https URI",
			uri:     "https://api.example.com/v1/certificates/cert-001",
			wantErr: false,
		},
		{
			name:    "valid http URI",
			uri:     "http://localhost:8080/v1/challenges/http-01",
			wantErr: false,
		},
		{
			name:    "valid URN URI",
			uri:     "urn:cert:cert-alpha",
			wantErr: false,
		},
		{
			name:    "empty URI",
			uri:     "",
			wantErr: true,
			errIs:   ErrInvalidTarget,
		},
		{
			name:    "relative path URI",
			uri:     "/v1/certificates/cert-001",
			wantErr: true,
			errIs:   ErrInvalidTarget,
		},
		{
			name:    "URI with fragment",
			uri:     "https://api.example.com/v1/certificates/cert-001#section",
			wantErr: true,
			errIs:   ErrInvalidTarget,
		},
		{
			name:    "malformed URI",
			uri:     "https://::invalid-host",
			wantErr: true,
			errIs:   ErrInvalidTarget,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateAbsoluteURI(tt.uri)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errIs != nil {
					require.ErrorIs(t, err, tt.errIs)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestToken_IsExpired_And_IsRevoked(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

	// Not expired, not revoked
	tokValid := &Token{
		ExpiresAt: now.Add(1 * time.Hour),
		RevokedAt: nil,
	}
	assert.False(t, tokValid.IsExpired(now))
	assert.False(t, tokValid.IsRevoked())

	// Expired
	tokExpired := &Token{
		ExpiresAt: now.Add(-1 * time.Minute),
	}
	assert.True(t, tokExpired.IsExpired(now))

	// Revoked
	revTime := now.Add(-10 * time.Minute)
	tokRevoked := &Token{
		ExpiresAt: now.Add(1 * time.Hour),
		RevokedAt: &revTime,
	}
	assert.True(t, tokRevoked.IsRevoked())
}
