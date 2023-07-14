package client

import (
	"context"

	service "github.com/babylonchain/btc-staker/stakerservice"
	jsonrpcclient "github.com/cometbft/cometbft/rpc/jsonrpc/client"
)

type StakerServiceJsonRpcClient struct {
	client *jsonrpcclient.Client
}

// TODO Add some kind of timeout config
func NewStakerServiceJsonRpcClient(remoteAddress string) (*StakerServiceJsonRpcClient, error) {
	client, err := jsonrpcclient.New(remoteAddress)
	if err != nil {
		return nil, err
	}

	return &StakerServiceJsonRpcClient{
		client: client,
	}, nil
}

func (c *StakerServiceJsonRpcClient) Health(ctx context.Context) (*service.ResultHealth, error) {
	result := new(service.ResultHealth)
	_, err := c.client.Call(ctx, "health", map[string]interface{}{}, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJsonRpcClient) ListOutputs(ctx context.Context) (*service.OutputsResponse, error) {
	result := new(service.OutputsResponse)
	_, err := c.client.Call(ctx, "list_outputs", map[string]interface{}{}, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
