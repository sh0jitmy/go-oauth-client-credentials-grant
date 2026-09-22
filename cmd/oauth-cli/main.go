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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/shjtmy/go-oauth-client-credentials-grant/pkg/oauth2"
	oauthClient "github.com/shjtmy/go-oauth-client-credentials-grant/pkg/oauth2/client"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "oauth-cli",
		Usage: "OAuth 2.0 RFC 8707 Client Credentials & ACME Challenge evaluation CLI tool",
		Commands: []*cli.Command{
			registerCommand(),
			tokenCommand(),
			challengeStartCommand(),
			challengeVerifyCommand(),
			challengeCompleteCommand(),
			getCertCommand(),
			introspectCommand(),
			revokeCommand(),
			callCommand(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func defaultServerURL() string {
	if u := os.Getenv("SERVER_URL"); u != "" {
		return u
	}
	return "http://localhost:8080"
}

func printPrettyJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// registerCommand registers an OAuth 2.0 client.
func registerCommand() *cli.Command {
	return &cli.Command{
		Name:  "register",
		Usage: "Register a new OAuth client on the authorization server",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "server-url", Value: defaultServerURL(), Usage: "Auth server base URL"},
			&cli.StringFlag{Name: "name", Required: true, Usage: "Client organization / service name"},
			&cli.StringFlag{Name: "resources", Usage: "Comma-separated list of allowed RFC 8707 absolute URIs"},
			&cli.StringFlag{Name: "scopes", Usage: "Space-separated allowed scopes (e.g. 'cert:issue cert:revoke')"},
		},
		Action: func(c *cli.Context) error {
			serverURL := c.String("server-url")
			name := c.String("name")
			var resources []string
			if raw := c.String("resources"); raw != "" {
				for _, r := range strings.Split(raw, ",") {
					if tr := strings.TrimSpace(r); tr != "" {
						resources = append(resources, tr)
					}
				}
			}

			var scopes []string
			if rawScopes := c.String("scopes"); rawScopes != "" {
				scopes = strings.Fields(rawScopes)
			}

			client := oauthClient.New(oauthClient.Config{ServerURL: serverURL})
			resp, err := client.RegisterClient(c.Context, &oauth2.RegisterClientRequest{
				Name:             name,
				AllowedResources: resources,
				AllowedScopes:    scopes,
			})
			if err != nil {
				return fmt.Errorf("registration failed: %w", err)
			}

			fmt.Println("Client successfully registered:")
			return printPrettyJSON(resp)
		},
	}
}

// tokenCommand fetches an Opaque Access Token for an RFC 8707 resource.
func tokenCommand() *cli.Command {
	return &cli.Command{
		Name:  "token",
		Usage: "Acquire an Opaque Access Token for an RFC 8707 absolute URI resource",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "server-url", Value: defaultServerURL(), Usage: "Auth server base URL"},
			&cli.StringFlag{Name: "client-id", Required: true, EnvVars: []string{"CLIENT_ID"}, Usage: "OAuth Client ID"},
			&cli.StringFlag{Name: "client-secret", Required: true, EnvVars: []string{"CLIENT_SECRET"}, Usage: "OAuth Client Secret"},
			&cli.StringFlag{Name: "resource", Usage: "RFC 8707 target resource absolute URI"},
		},
		Action: func(c *cli.Context) error {
			client := oauthClient.New(oauthClient.Config{
				ServerURL:    c.String("server-url"),
				ClientID:     c.String("client-id"),
				ClientSecret: c.String("client-secret"),
			})

			token, err := client.GetToken(c.Context, c.String("resource"))
			if err != nil {
				return fmt.Errorf("failed to obtain token: %w", err)
			}

			fmt.Printf("Access Token: %s\n", token)
			return nil
		},
	}
}

// challengeStartCommand provisions an ACME HTTP-01 challenge.
func challengeStartCommand() *cli.Command {
	return &cli.Command{
		Name:  "challenge-start",
		Usage: "Request HTTP-01 challenge start for a certificate (protected API)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "server-url", Value: defaultServerURL(), Usage: "Target server base URL"},
			&cli.StringFlag{Name: "client-id", Required: true, EnvVars: []string{"CLIENT_ID"}, Usage: "OAuth Client ID"},
			&cli.StringFlag{Name: "client-secret", Required: true, EnvVars: []string{"CLIENT_SECRET"}, Usage: "OAuth Client Secret"},
			&cli.StringFlag{Name: "cert-id", Required: true, Usage: "Certificate ID (e.g. cert-001)"},
			&cli.StringFlag{Name: "domain", Required: true, Usage: "Domain name (e.g. example.com)"},
			&cli.StringFlag{Name: "token", Required: true, Usage: "ACME challenge token"},
			&cli.StringFlag{Name: "key-auth", Required: true, Usage: "ACME Key Authorization string"},
			&cli.StringFlag{Name: "resource-base-url", Value: "https://api.example.com", Usage: "RFC 8707 Resource Base URL"},
		},
		Action: func(c *cli.Context) error {
			serverURL := strings.TrimRight(c.String("server-url"), "/")
			certID := c.String("cert-id")
			resourceURI := fmt.Sprintf("%s/v1/certificates/%s", strings.TrimRight(c.String("resource-base-url"), "/"), certID)

			client := oauthClient.New(oauthClient.Config{
				ServerURL:    serverURL,
				ClientID:     c.String("client-id"),
				ClientSecret: c.String("client-secret"),
			})

			payload, _ := json.Marshal(map[string]string{
				"domain":            c.String("domain"),
				"token":             c.String("token"),
				"key_authorization": c.String("key-auth"),
			})

			endpoint := fmt.Sprintf("%s/v1/certificates/%s/challenges/http-01/start", serverURL, certID)
			httpReq, err := http.NewRequestWithContext(c.Context, http.MethodPost, endpoint, bytes.NewReader(payload))
			if err != nil {
				return err
			}
			httpReq.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(httpReq, resourceURI)
			if err != nil {
				return fmt.Errorf("API call failed: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("HTTP Status: %d\n", resp.StatusCode)
			var parsed any
			if json.Unmarshal(body, &parsed) == nil {
				return printPrettyJSON(parsed)
			}
			fmt.Println(string(body))
			return nil
		},
	}
}

// challengeVerifyCommand performs public unauthenticated verification of the challenge.
func challengeVerifyCommand() *cli.Command {
	return &cli.Command{
		Name:  "challenge-verify",
		Usage: "Verify public ACME HTTP-01 challenge response (GET /.well-known/acme-challenge/:token)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "server-url", Value: defaultServerURL(), Usage: "Server base URL"},
			&cli.StringFlag{Name: "token", Required: true, Usage: "ACME challenge token to fetch"},
		},
		Action: func(c *cli.Context) error {
			serverURL := strings.TrimRight(c.String("server-url"), "/")
			token := c.String("token")
			endpoint := fmt.Sprintf("%s/.well-known/acme-challenge/%s", serverURL, token)

			resp, err := http.Get(endpoint) //nolint:gosec,noctx // CLI user-specified target
			if err != nil {
				return fmt.Errorf("failed to fetch challenge: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("HTTP Status: %d\n", resp.StatusCode)
			fmt.Printf("Content-Type: %s\n", resp.Header.Get("Content-Type"))
			fmt.Printf("Key Authorization: %s\n", string(body))
			return nil
		},
	}
}

// challengeCompleteCommand completes the ACME challenge.
func challengeCompleteCommand() *cli.Command {
	return &cli.Command{
		Name:  "challenge-complete",
		Usage: "Complete and clean up HTTP-01 challenge (protected API)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "server-url", Value: defaultServerURL(), Usage: "Target server base URL"},
			&cli.StringFlag{Name: "client-id", Required: true, EnvVars: []string{"CLIENT_ID"}, Usage: "OAuth Client ID"},
			&cli.StringFlag{Name: "client-secret", Required: true, EnvVars: []string{"CLIENT_SECRET"}, Usage: "OAuth Client Secret"},
			&cli.StringFlag{Name: "cert-id", Required: true, Usage: "Certificate ID (e.g. cert-001)"},
			&cli.StringFlag{Name: "token", Required: true, Usage: "ACME challenge token"},
			&cli.StringFlag{Name: "resource-base-url", Value: "https://api.example.com", Usage: "RFC 8707 Resource Base URL"},
		},
		Action: func(c *cli.Context) error {
			serverURL := strings.TrimRight(c.String("server-url"), "/")
			certID := c.String("cert-id")
			resourceURI := fmt.Sprintf("%s/v1/certificates/%s", strings.TrimRight(c.String("resource-base-url"), "/"), certID)

			client := oauthClient.New(oauthClient.Config{
				ServerURL:    serverURL,
				ClientID:     c.String("client-id"),
				ClientSecret: c.String("client-secret"),
			})

			payload, _ := json.Marshal(map[string]string{
				"token": c.String("token"),
			})

			endpoint := fmt.Sprintf("%s/v1/certificates/%s/challenges/http-01/complete", serverURL, certID)
			httpReq, err := http.NewRequestWithContext(c.Context, http.MethodPost, endpoint, bytes.NewReader(payload))
			if err != nil {
				return err
			}
			httpReq.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(httpReq, resourceURI)
			if err != nil {
				return fmt.Errorf("API call failed: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("HTTP Status: %d\n", resp.StatusCode)
			var parsed any
			if json.Unmarshal(body, &parsed) == nil {
				return printPrettyJSON(parsed)
			}
			fmt.Println(string(body))
			return nil
		},
	}
}

// getCertCommand retrieves certificate metadata.
func getCertCommand() *cli.Command {
	return &cli.Command{
		Name:  "get-cert",
		Usage: "Retrieve certificate details (protected API)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "server-url", Value: defaultServerURL(), Usage: "Target server base URL"},
			&cli.StringFlag{Name: "client-id", Required: true, EnvVars: []string{"CLIENT_ID"}, Usage: "OAuth Client ID"},
			&cli.StringFlag{Name: "client-secret", Required: true, EnvVars: []string{"CLIENT_SECRET"}, Usage: "OAuth Client Secret"},
			&cli.StringFlag{Name: "cert-id", Required: true, Usage: "Certificate ID (e.g. cert-001)"},
			&cli.StringFlag{Name: "resource-base-url", Value: "https://api.example.com", Usage: "RFC 8707 Resource Base URL"},
		},
		Action: func(c *cli.Context) error {
			serverURL := strings.TrimRight(c.String("server-url"), "/")
			certID := c.String("cert-id")
			resourceURI := fmt.Sprintf("%s/v1/certificates/%s", strings.TrimRight(c.String("resource-base-url"), "/"), certID)

			client := oauthClient.New(oauthClient.Config{
				ServerURL:    serverURL,
				ClientID:     c.String("client-id"),
				ClientSecret: c.String("client-secret"),
			})

			endpoint := fmt.Sprintf("%s/v1/certificates/%s", serverURL, certID)
			httpReq, err := http.NewRequestWithContext(c.Context, http.MethodGet, endpoint, nil)
			if err != nil {
				return err
			}

			resp, err := client.Do(httpReq, resourceURI)
			if err != nil {
				return fmt.Errorf("API call failed: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("HTTP Status: %d\n", resp.StatusCode)
			var parsed any
			if json.Unmarshal(body, &parsed) == nil {
				return printPrettyJSON(parsed)
			}
			fmt.Println(string(body))
			return nil
		},
	}
}

// introspectCommand inspects an active token.
func introspectCommand() *cli.Command {
	return &cli.Command{
		Name:  "introspect",
		Usage: "Introspect an access token (RFC 7662)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "server-url", Value: defaultServerURL(), Usage: "Auth server base URL"},
			&cli.StringFlag{Name: "client-id", Required: true, EnvVars: []string{"CLIENT_ID"}, Usage: "OAuth Client ID"},
			&cli.StringFlag{Name: "client-secret", Required: true, EnvVars: []string{"CLIENT_SECRET"}, Usage: "OAuth Client Secret"},
			&cli.StringFlag{Name: "token", Required: true, Usage: "Access token to introspect"},
		},
		Action: func(c *cli.Context) error {
			client := oauthClient.New(oauthClient.Config{
				ServerURL:    c.String("server-url"),
				ClientID:     c.String("client-id"),
				ClientSecret: c.String("client-secret"),
			})

			resp, err := client.Introspect(c.Context, c.String("token"))
			if err != nil {
				return fmt.Errorf("introspection failed: %w", err)
			}

			fmt.Println("Introspection Response:")
			return printPrettyJSON(resp)
		},
	}
}

// revokeCommand revokes a token.
func revokeCommand() *cli.Command {
	return &cli.Command{
		Name:  "revoke",
		Usage: "Revoke an access token (RFC 7009)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "server-url", Value: defaultServerURL(), Usage: "Auth server base URL"},
			&cli.StringFlag{Name: "client-id", Required: true, EnvVars: []string{"CLIENT_ID"}, Usage: "OAuth Client ID"},
			&cli.StringFlag{Name: "client-secret", Required: true, EnvVars: []string{"CLIENT_SECRET"}, Usage: "OAuth Client Secret"},
			&cli.StringFlag{Name: "token", Required: true, Usage: "Access token to revoke"},
		},
		Action: func(c *cli.Context) error {
			client := oauthClient.New(oauthClient.Config{
				ServerURL:    c.String("server-url"),
				ClientID:     c.String("client-id"),
				ClientSecret: c.String("client-secret"),
			})

			if err := client.Revoke(c.Context, c.String("token")); err != nil {
				return fmt.Errorf("revocation failed: %w", err)
			}

			fmt.Println("Token revoked successfully.")
			return nil
		},
	}
}

// callCommand executes an arbitrary authenticated API call.
func callCommand() *cli.Command {
	return &cli.Command{
		Name:  "call",
		Usage: "Execute an arbitrary HTTP request authenticated with OAuth 2.0 Bearer token",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "server-url", Value: defaultServerURL(), Usage: "Target server base URL"},
			&cli.StringFlag{Name: "client-id", Required: true, EnvVars: []string{"CLIENT_ID"}, Usage: "OAuth Client ID"},
			&cli.StringFlag{Name: "client-secret", Required: true, EnvVars: []string{"CLIENT_SECRET"}, Usage: "OAuth Client Secret"},
			&cli.StringFlag{Name: "resource", Usage: "RFC 8707 target resource URI (defaults to full request URL)"},
			&cli.StringFlag{Name: "method", Value: "GET", Usage: "HTTP Method (GET, POST, PUT, DELETE)"},
			&cli.StringFlag{Name: "path", Required: true, Usage: "Request Path (e.g. /v1/certificates/cert-001)"},
			&cli.StringFlag{Name: "body", Usage: "JSON request body payload"},
		},
		Action: func(c *cli.Context) error {
			serverURL := strings.TrimRight(c.String("server-url"), "/")
			client := oauthClient.New(oauthClient.Config{
				ServerURL:    serverURL,
				ClientID:     c.String("client-id"),
				ClientSecret: c.String("client-secret"),
			})

			endpoint := serverURL + c.String("path")
			var bodyReader io.Reader
			if rawBody := c.String("body"); rawBody != "" {
				bodyReader = strings.NewReader(rawBody)
			}

			httpReq, err := http.NewRequestWithContext(c.Context, c.String("method"), endpoint, bodyReader)
			if err != nil {
				return err
			}
			if bodyReader != nil {
				httpReq.Header.Set("Content-Type", "application/json")
			}

			resource := c.String("resource")
			resp, err := client.Do(httpReq, resource)
			if err != nil {
				return fmt.Errorf("request execution failed: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("HTTP Status: %d\n", resp.StatusCode)
			var parsed any
			if json.Unmarshal(body, &parsed) == nil {
				return printPrettyJSON(parsed)
			}
			fmt.Println(string(body))
			return nil
		},
	}
}
