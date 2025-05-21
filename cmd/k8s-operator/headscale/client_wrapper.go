package headscale

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	headscale "github.com/juanfont/headscale/gen/go/headscale/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"
	"tailscale.com/client/tailscale"
	_tailscale "tailscale.com/internal/client/tailscale"
	"tailscale.com/tailcfg"
)

// HeadscaleClientWrapper implements the tsClient interface for Headscale.
type HeadscaleClientWrapper struct {
	client headscale.HeadscaleServiceClient
	// NOTE: in headscale, user and network
	// are the same thing
	user string
}

// NewHeadscaleClientWrapper instantiates a new HeadscaleClientWrapper.
func NewHeadscaleClientWrapper(ctx context.Context, zlog *zap.SugaredLogger) *HeadscaleClientWrapper {
	apiAddress, set := os.LookupEnv("HEADSCALE_GRPC_ADDRESS")
	if !set {
		zlog.Fatalf("HEADSCALE_GRPC_ADDRESS must be set")
	}
	user, set := os.LookupEnv("HEADSCALE_USER")
	if !set {
		zlog.Fatalf("HEADSCALE_USER must be set")
	}
	apiKey, set := os.LookupEnv("HEADSCALE_API_KEY")
	if !set {
		zlog.Fatalf("HEADSCALE_API_KEY must be set")
	}

	grpcOptions := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithPerRPCCredentials(tokenAuth{token: apiKey}),
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
	}

	conn, err := grpc.DialContext(ctx, apiAddress, grpcOptions...)
	if err != nil {
		zlog.Fatalf("Error creating Headscale API client: %v", err)
	}

	return &HeadscaleClientWrapper{
		client: headscale.NewHeadscaleServiceClient(conn),
		user:   user,
	}
}

func (c *HeadscaleClientWrapper) CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (keySecret string, keyMeta *tailscale.Key, _ error) {
	resp, err := c.client.CreatePreAuthKey(ctx, &headscale.CreatePreAuthKeyRequest{
		User:      c.user,
		Reusable:  caps.Devices.Create.Reusable,
		Ephemeral: caps.Devices.Create.Ephemeral,
		AclTags:   caps.Devices.Create.Tags,
		// According to the Tailscale API docs,
		// 90 days is the default.
		Expiration: timestamppb.New(time.Now().UTC().Add(time.Hour * 24 * 90)),
	})
	if err != nil {
		return "", nil, err
	}

	keySecret = resp.PreAuthKey.Key
	keyMeta = &tailscale.Key{
		ID:      resp.PreAuthKey.Id,
		Created: resp.PreAuthKey.CreatedAt.AsTime(),
		Expires: resp.PreAuthKey.Expiration.AsTime(),
	}

	return keySecret, keyMeta, nil
}

func (c *HeadscaleClientWrapper) Device(ctx context.Context, deviceID string, fields *tailscale.DeviceFieldsOpts) (*tailscale.Device, error) {
	deviceIDInt, err := strconv.Atoi(deviceID)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.GetNode(ctx, &headscale.GetNodeRequest{
		NodeId: uint64(deviceIDInt),
	})
	if err != nil {
		return nil, err
	}

	var node = resp.Node

	return &tailscale.Device{
		Addresses: node.IpAddresses,
		DeviceID:  fmt.Sprint(node.Id),
		NodeID:    fmt.Sprint(node.Id),
		User:      node.User.Name,
		Name:      node.Name,
		Hostname:  node.GivenName,

		ClientVersion:   "",      // Mock
		UpdateAvailable: false,   // Mock
		OS:              "Linux", // Mock, most likely OS for Kubernetes

		Tags:              node.ValidTags,
		Created:           node.CreatedAt.String(),
		LastSeen:          node.LastSeen.String(),
		KeyExpiryDisabled: false, // Mock, keys are created with 90d expiry, see CreateKey()
		Expires:           node.Expiry.String(),
		Authorized:        true,  // Mock, should be true (?)
		IsExternal:        false, // Mock, Headscale doesn't have external devices
		MachineKey:        node.MachineKey,
		NodeKey:           node.NodeKey,
	}, nil
}

func (c *HeadscaleClientWrapper) DeleteDevice(ctx context.Context, nodeStableID string) error {
	resp, err := c.client.ListNodes(ctx, &headscale.ListNodesRequest{
		User: c.user,
	})
	if err != nil {
		return err
	}

	for _, node := range resp.Nodes {
		// TODO: Headscale uses simple numeric node IDs
		// which can be reused after deletion.
		// To avoid accidentally deleting the wrong node,
		// we should also check the node name.
		if fmt.Sprint(node.Id) == nodeStableID {
			_, err := c.client.DeleteNode(ctx, &headscale.DeleteNodeRequest{
				NodeId: node.Id,
			})
			return err
		}
	}

	return nil
}

func (c *HeadscaleClientWrapper) GetVIPService(ctx context.Context, name tailcfg.ServiceName) (*_tailscale.VIPService, error) {
	return nil, fmt.Errorf("VIPService not supported for Headscale")
}

func (c *HeadscaleClientWrapper) CreateOrUpdateVIPService(ctx context.Context, svc *_tailscale.VIPService) error {
	return fmt.Errorf("VIPService not supported for Headscale")
}

func (c *HeadscaleClientWrapper) DeleteVIPService(ctx context.Context, name tailcfg.ServiceName) error {
	return fmt.Errorf("VIPService not supported for Headscale")
}

// tokenAuth is a helper type that implements the PerRPCCredentials interface.
// source:
// https://github.com/juanfont/headscale/blob/main/cmd/headscale/cli/utils.go
type tokenAuth struct {
	token string
}

// Return value is mapped to request headers.
func (t tokenAuth) GetRequestMetadata(
	ctx context.Context,
	in ...string,
) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (tokenAuth) RequireTransportSecurity() bool {
	return true
}
