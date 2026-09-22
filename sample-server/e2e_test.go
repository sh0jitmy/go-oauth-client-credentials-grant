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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shjtmy/go-oauth-client-credentials-grant/pkg/oauth2"
	oauthClient "github.com/shjtmy/go-oauth-client-credentials-grant/pkg/oauth2/client"
	"github.com/shjtmy/go-oauth-client-credentials-grant/sample-server/internal/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestServer() (*httptest.Server, *oauth2.Service) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	oauthStore := oauth2.NewMemoryStore()
	oauthSvc := oauth2.NewService(oauthStore, oauth2.WithTokenTTL(3600*time.Second), oauth2.WithBcryptCost(4))

	certStore := certificate.NewMemoryStore()
	certHandler := certificate.NewHandler(certStore)

	oauth2.RegisterRoutes(r.Group("/oauth"), oauthSvc)
	r.GET("/.well-known/acme-challenge/:token", certHandler.ServeACMEChallenge)

	resourceBaseURL := "https://api.example.com"
	resourceExtractor := func(c *gin.Context) string {
		certID := c.Param("id")
		return strings.TrimRight(resourceBaseURL, "/") + "/v1/certificates/" + certID
	}

	v1 := r.Group("/v1")
	v1.Use(oauth2.TokenAuthMiddleware(oauthSvc))
	v1.Use(oauth2.RequireResource(resourceExtractor))
	{
		v1.POST("/certificates/:id/challenges/http-01/start", certHandler.StartChallenge)
		v1.POST("/certificates/:id/challenges/http-01/complete", certHandler.CompleteChallenge)
		v1.GET("/certificates/:id", certHandler.GetCertificate)
	}

	ts := httptest.NewServer(r)
	return ts, oauthSvc
}

func TestE2E_FullOAuthAndACMEChallengeFlow(t *testing.T) {
	t.Parallel()
	ts, _ := setupTestServer()
	defer ts.Close()

	ctx := context.Background()

	// 1. Client Registration (POST /oauth/clients)
	// Bind client to specific resource URI: https://api.example.com/v1/certificates/cert-001
	allowedResource := "https://api.example.com/v1/certificates/cert-001"
	regClient := oauthClient.New(oauthClient.Config{ServerURL: ts.URL})

	regResp, err := regClient.RegisterClient(ctx, &oauth2.RegisterClientRequest{
		Name:             "ACME Automation Worker",
		AllowedResources: []string{allowedResource},
		AllowedScopes:    []string{"cert:manage"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, regResp.ClientID)
	require.NotEmpty(t, regResp.ClientSecret)

	// Configure SDK client with issued credentials
	cli := oauthClient.New(oauthClient.Config{
		ServerURL:    ts.URL,
		ClientID:     regResp.ClientID,
		ClientSecret: regResp.ClientSecret,
	})

	// 2. Reject Token Request for Unauthorized Resource (RFC 8707)
	unauthorizedResource := "https://api.example.com/v1/certificates/cert-999"
	_, err = cli.GetToken(ctx, unauthorizedResource)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_target")

	// 3. Acquire Token for Authorized Resource
	token, err := cli.GetToken(ctx, allowedResource)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// 4. Introspect Active Token (RFC 7662)
	introResp, err := cli.Introspect(ctx, token)
	require.NoError(t, err)
	assert.True(t, introResp.Active)
	assert.Equal(t, regResp.ClientID, introResp.ClientID)
	assert.Equal(t, allowedResource, introResp.Resource)

	// 5. Start ACME HTTP-01 Challenge (Protected API)
	acmeToken := "token-e2e-abc-123"                       //nolint:gosec // false positive for test token
	keyAuth := "token-e2e-abc-123.auth-key-thumbprint-xyz" //nolint:gosec // false positive for test token
	startPayload, _ := json.Marshal(certificate.StartChallengeRequest{
		Domain:           "test.example.com",
		Token:            acmeToken,
		KeyAuthorization: keyAuth,
	})

	startReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/v1/certificates/cert-001/challenges/http-01/start", bytes.NewReader(startPayload))
	require.NoError(t, err)
	startReq.Header.Set("Content-Type", "application/json")

	startResp, err := cli.Do(startReq, allowedResource)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, startResp.StatusCode)
	startRespBody, _ := io.ReadAll(startResp.Body)
	_ = startResp.Body.Close()

	var startResult certificate.StartChallengeResponse
	err = json.Unmarshal(startRespBody, &startResult)
	require.NoError(t, err)
	assert.Equal(t, "cert-001", startResult.CertificateID)
	assert.Equal(t, "pending", startResult.Status)
	assert.Equal(t, "/.well-known/acme-challenge/"+acmeToken, startResult.ChallengePath)

	// 6. Public Unauthenticated ACME HTTP-01 Challenge Verification (RFC 8555 Section 8.3)
	publicResp, err := http.Get(ts.URL + "/.well-known/acme-challenge/" + acmeToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, publicResp.StatusCode)
	publicBody, _ := io.ReadAll(publicResp.Body)
	_ = publicResp.Body.Close()
	assert.Equal(t, keyAuth, string(publicBody))

	// 7. Inspect Certificate Status (pending)
	getCertReq, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/certificates/cert-001", nil)
	require.NoError(t, err)
	getCertResp, err := cli.Do(getCertReq, allowedResource)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, getCertResp.StatusCode)
	var certRecord certificate.Certificate
	_ = json.NewDecoder(getCertResp.Body).Decode(&certRecord)
	_ = getCertResp.Body.Close()
	assert.Equal(t, "pending", certRecord.Status)

	// 8. Complete ACME HTTP-01 Challenge (Protected API)
	completePayload, _ := json.Marshal(certificate.CompleteChallengeRequest{
		Token: acmeToken,
	})
	completeReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/v1/certificates/cert-001/challenges/http-01/complete", bytes.NewReader(completePayload))
	require.NoError(t, err)
	completeReq.Header.Set("Content-Type", "application/json")

	completeResp, err := cli.Do(completeReq, allowedResource)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, completeResp.StatusCode)
	var completeResult certificate.CompleteChallengeResponse
	_ = json.NewDecoder(completeResp.Body).Decode(&completeResult)
	_ = completeResp.Body.Close()
	assert.Equal(t, "issued", completeResult.Status)

	// 9. Verify Public Challenge is Cleaned Up (404 Not Found)
	cleanupResp, err := http.Get(ts.URL + "/.well-known/acme-challenge/" + acmeToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, cleanupResp.StatusCode)
	_ = cleanupResp.Body.Close()

	// 10. Verify Certificate Status is now "issued"
	getCertReq2, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/certificates/cert-001", nil)
	require.NoError(t, err)
	getCertResp2, err := cli.Do(getCertReq2, allowedResource)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, getCertResp2.StatusCode)
	var certRecord2 certificate.Certificate
	_ = json.NewDecoder(getCertResp2.Body).Decode(&certRecord2)
	_ = getCertResp2.Body.Close()
	assert.Equal(t, "issued", certRecord2.Status)

	// 11. Security Check: Accessing with Invalid / Missing Bearer Token -> 401 Unauthorized
	unauthedReq, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/certificates/cert-001", nil)
	require.NoError(t, err)
	unauthedResp, err := http.DefaultClient.Do(unauthedReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, unauthedResp.StatusCode)
	_ = unauthedResp.Body.Close()

	// 12. Security Check: Accessing with Malformed Bearer Token -> 401 Unauthorized
	badTokenReq, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/certificates/cert-001", nil)
	require.NoError(t, err)
	badTokenReq.Header.Set("Authorization", "Bearer invalid-tampered-token")
	badTokenResp, err := http.DefaultClient.Do(badTokenReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, badTokenResp.StatusCode)
	_ = badTokenResp.Body.Close()

	// 13. Revoke Token (RFC 7009)
	err = cli.Revoke(ctx, token)
	require.NoError(t, err)

	// 14. Verify Token is Inactive via Introspect -> active: false
	introAfterRevoke, err := cli.Introspect(ctx, token)
	require.NoError(t, err)
	assert.False(t, introAfterRevoke.Active)

	// 15. Verify API Request with Revoked Token -> 401 Unauthorized
	revokedReq, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/v1/certificates/cert-001", nil)
	require.NoError(t, err)
	revokedReq.Header.Set("Authorization", "Bearer "+token)
	revokedResp, err := http.DefaultClient.Do(revokedReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, revokedResp.StatusCode)
	_ = revokedResp.Body.Close()
}
