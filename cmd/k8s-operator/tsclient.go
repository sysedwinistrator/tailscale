// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"os"

	"go.uber.org/zap"
	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/cmd/k8s-operator/headscale"
	"tailscale.com/internal/client/tailscale"
	"tailscale.com/tailcfg"
)

// defaultTailnet is a value that can be used in Tailscale API calls instead of tailnet name to indicate that the API
// call should be performed on the default tailnet for the provided credentials.
const (
	defaultTailnet = "-"
	defaultBaseURL = "https://api.tailscale.com"
)

func newTSClient(ctx context.Context, zlog *zap.SugaredLogger, tokenURL, clientIDPath, clientSecretPath string) (client tsClient, err error) {
	switch backend := defaultEnv("OPERATOR_BACKEND", "tailscale"); backend {
	case "tailscale":
		clientID, err := os.ReadFile(clientIDPath)
		if err != nil {
			return nil, fmt.Errorf("error reading client ID %q: %w", clientIDPath, err)
		}
		clientSecret, err := os.ReadFile(clientSecretPath)
		if err != nil {
			return nil, fmt.Errorf("reading client secret %q: %w", clientSecretPath, err)
		}
		credentials := clientcredentials.Config{
			ClientID:     string(clientID),
			ClientSecret: string(clientSecret),
			TokenURL:     tokenURL,
		}
		c := tailscale.NewClient(defaultTailnet, nil)
		c.UserAgent = "tailscale-k8s-operator"
		c.HTTPClient = credentials.Client(ctx)
		client = c
	case "headscale":
		client = headscale.NewHeadscaleClientWrapper(context.Background(), zlog)
	default:
		return nil, fmt.Errorf("unsupported backend: %s", backend)
	}

	return client, nil
}

type tsClient interface {
	CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error)
	Device(ctx context.Context, deviceID string, fields *tailscale.DeviceFieldsOpts) (*tailscale.Device, error)
	DeleteDevice(ctx context.Context, nodeStableID string) error
	GetVIPService(ctx context.Context, name tailcfg.ServiceName) (*tailscale.VIPService, error)
	CreateOrUpdateVIPService(ctx context.Context, svc *tailscale.VIPService) error
	DeleteVIPService(ctx context.Context, name tailcfg.ServiceName) error
}
