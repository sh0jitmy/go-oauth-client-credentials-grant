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
	"time"
)

// Certificate represents a managed TLS certificate.
type Certificate struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Status    string    `json:"status"` // "pending", "issued", "revoked"
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// HTTP01Challenge represents an ACME HTTP-01 challenge fulfillment record.
type HTTP01Challenge struct {
	CertificateID    string    `json:"certificate_id"`
	Domain           string    `json:"domain"`
	Token            string    `json:"token"`
	KeyAuthorization string    `json:"key_authorization"`
	Status           string    `json:"status"` // "pending", "valid", "cleaned"
	CreatedAt        time.Time `json:"created_at"`
}

// StartChallengeRequest represents input for starting an ACME HTTP-01 challenge.
type StartChallengeRequest struct {
	Domain           string `json:"domain"`
	Token            string `json:"token"`
	KeyAuthorization string `json:"key_authorization"`
}

// StartChallengeResponse represents output when an ACME HTTP-01 challenge is provisioned.
type StartChallengeResponse struct {
	CertificateID string `json:"certificate_id"`
	Status        string `json:"status"`
	ChallengePath string `json:"challenge_path"`
	Message       string `json:"message"`
}

// CompleteChallengeRequest represents input for completing an ACME HTTP-01 challenge.
type CompleteChallengeRequest struct {
	Token string `json:"token"`
}

// CompleteChallengeResponse represents output when an ACME HTTP-01 challenge is cleaned up.
type CompleteChallengeResponse struct {
	CertificateID string `json:"certificate_id"`
	Status        string `json:"status"`
	Message       string `json:"message"`
}
