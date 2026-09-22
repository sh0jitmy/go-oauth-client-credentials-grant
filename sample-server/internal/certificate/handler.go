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
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Handler handles ACME HTTP-01 challenge operations and certificate inspection.
type Handler struct {
	store Store
}

// NewHandler initializes a new certificate Handler.
func NewHandler(store Store) *Handler {
	return &Handler{
		store: store,
	}
}

// StartChallenge starts the HTTP-01 challenge fulfillment for a certificate.
// POST /v1/certificates/:id/challenges/http-01/start
func (h *Handler) StartChallenge(c *gin.Context) {
	certID := c.Param("id")
	if certID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Certificate ID is required"})
		return
	}

	var req StartChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Malformed JSON payload: " + err.Error()})
		return
	}

	if req.Domain == "" || req.Token == "" || req.KeyAuthorization == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "domain, token, and key_authorization are all required",
		})
		return
	}

	now := time.Now().UTC()

	// Ensure certificate record exists or create pending
	if _, err := h.store.GetCertificate(c.Request.Context(), certID); err != nil {
		if errors.Is(err, ErrCertificateNotFound) {
			cert := &Certificate{
				ID:        certID,
				Domain:    req.Domain,
				Status:    "pending",
				CreatedAt: now,
			}
			if saveErr := h.store.SaveCertificate(c.Request.Context(), cert); saveErr != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "error_description": "Failed to save certificate record"})
				return
			}
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "error_description": err.Error()})
			return
		}
	}

	challenge := &HTTP01Challenge{
		CertificateID:    certID,
		Domain:           req.Domain,
		Token:            req.Token,
		KeyAuthorization: req.KeyAuthorization,
		Status:           "pending",
		CreatedAt:        now,
	}

	if err := h.store.SaveChallenge(c.Request.Context(), challenge); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "error_description": "Failed to save challenge record"})
		return
	}

	c.JSON(http.StatusCreated, StartChallengeResponse{
		CertificateID: certID,
		Status:        "pending",
		ChallengePath: fmt.Sprintf("/.well-known/acme-challenge/%s", req.Token),
		Message:       "ACME HTTP-01 challenge provisioned successfully",
	})
}

// CompleteChallenge finalizes and cleans up the HTTP-01 challenge.
// POST /v1/certificates/:id/challenges/http-01/complete
func (h *Handler) CompleteChallenge(c *gin.Context) {
	certID := c.Param("id")
	if certID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Certificate ID is required"})
		return
	}

	var req CompleteChallengeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Malformed JSON payload: " + err.Error()})
		return
	}

	if req.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Token is required"})
		return
	}

	// Remove provisioned challenge
	if err := h.store.DeleteChallenge(c.Request.Context(), req.Token); err != nil {
		if errors.Is(err, ErrChallengeNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "Challenge token not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "error_description": err.Error()})
		return
	}

	now := time.Now().UTC()
	cert, err := h.store.GetCertificate(c.Request.Context(), certID)
	if err != nil {
		if errors.Is(err, ErrCertificateNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "Certificate not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "error_description": err.Error()})
		return
	}

	cert.Status = "issued"
	cert.ExpiresAt = now.Add(90 * 24 * time.Hour) // 90 days validity
	if err := h.store.SaveCertificate(c.Request.Context(), cert); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "error_description": "Failed to update certificate status"})
		return
	}

	c.JSON(http.StatusOK, CompleteChallengeResponse{
		CertificateID: certID,
		Status:        cert.Status,
		Message:       "ACME HTTP-01 challenge completed and cleaned up successfully",
	})
}

// GetCertificate returns certificate details.
// GET /v1/certificates/:id
func (h *Handler) GetCertificate(c *gin.Context) {
	certID := c.Param("id")
	if certID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Certificate ID is required"})
		return
	}

	cert, err := h.store.GetCertificate(c.Request.Context(), certID)
	if err != nil {
		if errors.Is(err, ErrCertificateNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "error_description": "Certificate not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, cert)
}

// ServeACMEChallenge fulfills RFC 8555 Section 8.3 GET /.well-known/acme-challenge/:token.
// This is an unauthenticated public endpoint.
func (h *Handler) ServeACMEChallenge(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		c.String(http.StatusBadRequest, "Invalid token")
		return
	}

	challenge, err := h.store.GetChallenge(c.Request.Context(), token)
	if err != nil {
		if errors.Is(err, ErrChallengeNotFound) {
			c.String(http.StatusNotFound, "Challenge not found")
			return
		}
		c.String(http.StatusInternalServerError, "Internal error")
		return
	}

	// RFC 8555 Section 8.3: "Content-Type: application/octet-stream" or text/plain
	c.Data(http.StatusOK, "application/octet-stream", []byte(challenge.KeyAuthorization))
}
