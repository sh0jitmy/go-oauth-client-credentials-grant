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
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes registers standard OAuth 2.0 endpoints under the given Gin router group.
func RegisterRoutes(r *gin.RouterGroup, svc *Service) {
	r.POST("/clients", RegisterClientHandler(svc))
	r.POST("/token", TokenHandler(svc))
	r.POST("/introspect", IntrospectHandler(svc))
	r.POST("/revoke", RevokeHandler(svc))
}

// RegisterClientHandler returns a Gin handler for client registration.
func RegisterClientHandler(svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req RegisterClientRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "Failed to parse JSON body: " + err.Error(),
			})
			return
		}

		resp, err := svc.RegisterClient(c.Request.Context(), &req)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}

		c.JSON(http.StatusCreated, resp)
	}
}

// TokenHandler returns a Gin handler for the OAuth 2.0 token endpoint (RFC 6749 & RFC 8707).
func TokenHandler(svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req TokenRequest

		// Support both application/json and application/x-www-form-urlencoded
		contentType := c.ContentType()
		if strings.Contains(contentType, "application/json") {
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_request",
					"error_description": "Failed to parse JSON: " + err.Error(),
				})
				return
			}
		} else {
			if err := c.ShouldBind(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_request",
					"error_description": "Failed to parse form: " + err.Error(),
				})
				return
			}
		}

		// Support HTTP Basic Authentication (RFC 6749 Section 2.3.1)
		if clientID, clientSecret, ok := c.Request.BasicAuth(); ok {
			req.ClientID = clientID
			req.ClientSecret = clientSecret
		}

		resp, err := svc.IssueToken(c.Request.Context(), &req)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidClient):
				c.Header("WWW-Authenticate", `Basic realm="oauth2"`)
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":             "invalid_client",
					"error_description": "Client authentication failed",
				})
			case errors.Is(err, ErrInvalidGrant):
				c.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_grant",
					"error_description": "Unsupported grant_type (must be client_credentials)",
				})
			case errors.Is(err, ErrInvalidTarget):
				c.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_target",
					"error_description": err.Error(),
				})
			case errors.Is(err, ErrScopeMismatch):
				c.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_scope",
					"error_description": "Requested scope not authorized for this client",
				})
			default:
				c.JSON(http.StatusBadRequest, gin.H{
					"error":             "invalid_request",
					"error_description": err.Error(),
				})
			}
			return
		}

		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.JSON(http.StatusOK, resp)
	}
}

// IntrospectHandler returns a Gin handler for RFC 7662 token introspection.
func IntrospectHandler(svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractTokenParam(c)
		if token == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "Missing token parameter",
			})
			return
		}

		resp, err := svc.IntrospectToken(c.Request.Context(), token)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

// RevokeHandler returns a Gin handler for RFC 7009 token revocation.
func RevokeHandler(svc *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractTokenParam(c)
		if token == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "Missing token parameter",
			})
			return
		}

		if err := svc.RevokeToken(c.Request.Context(), token); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": err.Error(),
			})
			return
		}

		// RFC 7009 Section 2.2: HTTP 200 OK on successful revocation
		c.Status(http.StatusOK)
	}
}

func extractTokenParam(c *gin.Context) string {
	_ = c.Request.ParseForm()
	if token := c.PostForm("token"); token != "" {
		return token
	}
	if token := c.Query("token"); token != "" {
		return token
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&body); err == nil && body.Token != "" {
		return body.Token
	}
	return ""
}
