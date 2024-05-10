package service

import (
	"context"

	"github.com/babylonchain/btc-staker/cmd/stakercli/helpers"
	dc "github.com/babylonchain/btc-staker/stakerservice/client"
	"github.com/urfave/cli"
)

func Stake(stakerAddress string, stakingAmount int64, fpPks []string, stakingTimeBlocks int64, daemonAddress string) error {
	client, err := dc.NewStakerServiceJsonRpcClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	results, err := client.Stake(sctx, stakerAddress, stakingAmount, fpPks, stakingTimeBlocks)
	if err != nil {
		return err
	}

	helpers.PrintRespJSON(results)

	return nil
}

func Unbond(daemonAddress string, stakingTransactionHash string, feeRate int) error {
	client, err := dc.NewStakerServiceJsonRpcClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	if feeRate < 0 {
		return cli.NewExitError("Fee rate must be non-negative", 1)
	}

	var fr *int = nil
	if feeRate > 0 {
		fr = &feeRate
	}

	result, err := client.UnbondStaking(sctx, stakingTransactionHash, fr)
	if err != nil {
		return err
	}

	helpers.PrintRespJSON(result)

	return nil
}
