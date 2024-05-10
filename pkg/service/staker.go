package service

import (
	"context"

	"github.com/babylonchain/btc-staker/cmd/stakercli/helpers"
	dc "github.com/babylonchain/btc-staker/stakerservice/client"
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
