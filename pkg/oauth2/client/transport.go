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

package client

import (
	"fmt"
	"net/http"
)

var _ http.RoundTripper = (*Transport)(nil)

// Transport is an http.RoundTripper that automatically acquires an Opaque Token
// and injects it as an Authorization: Bearer header on outgoing requests.
type Transport struct {
	client      *Client
	base        http.RoundTripper
	resourceURI string // Optional fixed resource URI override
}

// NewTransport returns a new Transport wrapping the base RoundTripper.
func NewTransport(c *Client, base http.RoundTripper, resourceURI ...string) *Transport {
	if base == nil {
		base = http.DefaultTransport
	}
	var res string
	if len(resourceURI) > 0 {
		res = resourceURI[0]
	}
	return &Transport{
		client:      c,
		base:        base,
		resourceURI: res,
	}
}

// RoundTrip acquires an access token and executes the HTTP request.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Determine resource URI: explicit override or target URL
	targetResource := t.resourceURI
	if targetResource == "" && req.URL != nil {
		targetResource = fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.URL.Host, req.URL.Path)
	}

	token, err := t.client.GetToken(req.Context(), targetResource)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire token for %q: %w", targetResource, err)
	}

	// Clone request to avoid mutating caller's original request headers
	clonedReq := req.Clone(req.Context())
	clonedReq.Header.Set("Authorization", "Bearer "+token)

	return t.base.RoundTrip(clonedReq)
}

// Do executes an HTTP request using the authenticated transport.
func (c *Client) Do(req *http.Request, resourceURI ...string) (*http.Response, error) {
	transport := NewTransport(c, c.httpClient.Transport, resourceURI...)
	return transport.RoundTrip(req)
}

// HTTPClient returns a standard *http.Client wired with the authenticated transport.
func (c *Client) HTTPClient(resourceURI ...string) *http.Client {
	return &http.Client{
		Transport: NewTransport(c, c.httpClient.Transport, resourceURI...),
		Timeout:   c.httpClient.Timeout,
	}
}
