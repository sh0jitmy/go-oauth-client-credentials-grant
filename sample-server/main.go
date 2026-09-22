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
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shjtmy/go-oauth-client-credentials-grant/pkg/oauth2"
	"github.com/shjtmy/go-oauth-client-credentials-grant/sample-server/internal/certificate"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	resourceBaseURL := os.Getenv("RESOURCE_BASE_URL")
	if resourceBaseURL == "" {
		resourceBaseURL = "https://api.example.com"
	}

	// Initialize OAuth 2.0 Store & Service
	oauthStore := oauth2.NewMemoryStore()
	oauthSvc := oauth2.NewService(oauthStore, oauth2.WithTokenTTL(3600*time.Second))

	// Initialize Certificate Store & Handler
	certStore := certificate.NewMemoryStore()
	certHandler := certificate.NewHandler(certStore)

	// Configure Gin Router
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()
		logger.Info("HTTP request",
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.Int("status", c.Writer.Status()),
			slog.Duration("latency", time.Since(start)),
			slog.String("client_ip", c.ClientIP()),
		)
	})

	// Health and Prometheus Metrics
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Register OAuth 2.0 Authorization Server Endpoints
	oauth2.RegisterRoutes(r.Group("/oauth"), oauthSvc)

	// Unauthenticated Public ACME HTTP-01 Challenge Endpoint (RFC 8555 Section 8.3)
	r.GET("/.well-known/acme-challenge/:token", certHandler.ServeACMEChallenge)

	// Resource extractor for RFC 8707 Absolute URI checking
	resourceExtractor := func(c *gin.Context) string {
		certID := c.Param("id")
		return strings.TrimRight(resourceBaseURL, "/") + "/v1/certificates/" + certID
	}

	// Protected Certificate & Challenge APIs
	v1 := r.Group("/v1")
	v1.Use(oauth2.TokenAuthMiddleware(oauthSvc))
	v1.Use(oauth2.RequireResource(resourceExtractor))
	{
		v1.POST("/certificates/:id/challenges/http-01/start", certHandler.StartChallenge)
		v1.POST("/certificates/:id/challenges/http-01/complete", certHandler.CompleteChallenge)
		v1.GET("/certificates/:id", certHandler.GetCertificate)
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		logger.Info("Starting sample server", slog.String("port", port), slog.String("resource_base_url", resourceBaseURL))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Server failed to start", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down sample server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", slog.String("error", err.Error()))
	}
	logger.Info("Sample server exited cleanly")
}
