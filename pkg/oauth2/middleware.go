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
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// TokenContextKey is the Gin context key where validated Token is stored.
	TokenContextKey = "oauth2_token" //nolint:gosec // Gin context key, not a credential
)

// GetTokenFromContext retrieves the validated OAuth 2.0 Token from the Gin context.
func GetTokenFromContext(c *gin.Context) (*Token, bool) {
	val, exists := c.Get(TokenContextKey)
	if !exists {
		return nil, false
	}
	token, ok := val.(*Token)
	return token, ok
}

// TokenAuthMiddleware validates Bearer Opaque Tokens and injects token info into Gin context.
func TokenAuthMiddleware(svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			svc.telemetry.RecordAuthCheck(c.Request.Context(), "missing_token", "", "", "", c.Request.URL.Path, c.Request.Method, ErrInvalidRequest)
			c.Header("WWW-Authenticate", `Bearer error="invalid_request", error_description="Missing Authorization header"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Missing Authorization header",
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
			svc.telemetry.RecordAuthCheck(c.Request.Context(), "invalid_token", "", "", "", c.Request.URL.Path, c.Request.Method, ErrInvalidRequest)
			c.Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="Malformed Bearer token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Malformed Authorization header format (expected Bearer <token>)",
			})
			return
		}

		rawToken := strings.TrimSpace(parts[1])
		token, err := svc.ValidateToken(c.Request.Context(), rawToken)
		if err != nil {
			statusTag := "invalid_token"
			errMsg := "Invalid token"
			switch {
			case errors.Is(err, ErrTokenExpired):
				statusTag = "expired_token"
				errMsg = "Token has expired"
			case errors.Is(err, ErrTokenRevoked):
				statusTag = "revoked_token"
				errMsg = "Token has been revoked"
			}

			svc.telemetry.RecordAuthCheck(c.Request.Context(), statusTag, "", "", "", c.Request.URL.Path, c.Request.Method, err)
			c.Header("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_token", error_description=%q`, errMsg))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": errMsg,
			})
			return
		}

		// Inject token into Gin context
		c.Set(TokenContextKey, token)
		svc.telemetry.RecordAuthCheck(c.Request.Context(), "ok", token.ClientID, token.Resource, "", c.Request.URL.Path, c.Request.Method, nil)
		c.Next()
	}
}

// RequireResource ensures the request target matches the token's bound RFC 8707 absolute URI.
func RequireResource(resourceExtractor func(c *gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := GetTokenFromContext(c)
		if !ok || token == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Token context missing",
			})
			return
		}

		// If token is bound to a specific resource, verify target match
		if token.Resource != "" {
			expectedResource := resourceExtractor(c)
			if expectedResource != token.Resource {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":             "insufficient_scope",
					"error_description": fmt.Sprintf("Token resource %q does not match requested resource %q", token.Resource, expectedResource),
				})
				return
			}
		}

		c.Next()
	}
}

// RequireScope verifies that the token contains the required scope.
func RequireScope(requiredScope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := GetTokenFromContext(c)
		if !ok || token == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "Token context missing",
			})
			return
		}

		if token.Scope != "" {
			scopes := strings.Fields(token.Scope)
			hasScope := false
			for _, sc := range scopes {
				if sc == requiredScope {
					hasScope = true
					break
				}
			}
			if !hasScope {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":             "insufficient_scope",
					"error_description": fmt.Sprintf("Required scope %q missing from token", requiredScope),
				})
				return
			}
		}

		c.Next()
	}
}
