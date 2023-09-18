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

func (c *StakerServiceJsonRpcClient) BabylonValidators(ctx context.Context, offset *int, limit *int) (*service.ValidatorsResponse, error) {
	result := new(service.ValidatorsResponse)

	params := make(map[string]interface{})

	if limit != nil {
		params["limit"] = limit
	}

	if offset != nil {
		params["offset"] = offset
	}

	_, err := c.client.Call(ctx, "babylon_validators", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJsonRpcClient) Stake(ctx context.Context,
	stakerAddress string,
	stakingAmount int64,
	validatorPk string,
	stakingTimeBlocks int64,
) (*service.ResultStake, error) {
	result := new(service.ResultStake)

	params := make(map[string]interface{})
	params["stakerAddress"] = stakerAddress
	params["stakingAmount"] = stakingAmount
	params["validatorPk"] = validatorPk
	params["stakingTimeBlocks"] = stakingTimeBlocks

	_, err := c.client.Call(ctx, "stake", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJsonRpcClient) ListStakingTransactions(ctx context.Context, offset *int, limit *int) (*service.ListStakingTransactionsResponse, error) {
	result := new(service.ListStakingTransactionsResponse)

	params := make(map[string]interface{})

	if limit != nil {
		params["limit"] = limit
	}

	if offset != nil {
		params["offset"] = offset
	}

	_, err := c.client.Call(ctx, "list_staking_transactions", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJsonRpcClient) StakingDetails(ctx context.Context, txHash string) (*service.StakingDetails, error) {
	result := new(service.StakingDetails)

	params := make(map[string]interface{})
	params["stakingTxHash"] = txHash

	_, err := c.client.Call(ctx, "staking_details", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJsonRpcClient) SpendStakingTransaction(ctx context.Context, txHash string) (*service.SpendTxDetails, error) {
	result := new(service.SpendTxDetails)

	params := make(map[string]interface{})
	params["stakingTxHash"] = txHash

	_, err := c.client.Call(ctx, "spend_stake", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJsonRpcClient) WatchStaking(
	ctx context.Context,
	stakingTx string,
	stakingScript string,
	slashingTx string,
	slashingTxSig string,
	stakerBabylonPk string,
	stakerAddress string,
	stakerBabylonSig string,
	stakerBtcSig string,
	popType int,
) (*service.ResultStake, error) {

	result := new(service.ResultStake)
	params := make(map[string]interface{})

	params["stakingTx"] = stakingTx
	params["stakingScript"] = stakingScript
	params["slashingTx"] = slashingTx
	params["slashingTxSig"] = slashingTxSig
	params["stakerBabylonPk"] = stakerBabylonPk
	params["stakerAddress"] = stakerAddress
	params["stakerBabylonSig"] = stakerBabylonSig
	params["stakerBtcSig"] = stakerBtcSig
	params["popType"] = popType

	_, err := c.client.Call(ctx, "watch_staking_tx", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (c *StakerServiceJsonRpcClient) UnbondStaking(ctx context.Context, txHash string, feeRate *int) (*service.UnbondingResponse, error) {
	result := new(service.UnbondingResponse)

	params := make(map[string]interface{})
	params["stakingTxHash"] = txHash

	if feeRate != nil {
		params["feeRate"] = feeRate
	}

	_, err := c.client.Call(ctx, "unbond_staking", params, result)

	if err != nil {
		return nil, err
	}
	return result, nil
}
