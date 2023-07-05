package staker

import (
	"fmt"

	staking "github.com/babylonchain/babylon/btcstaking"
	cl "github.com/babylonchain/btc-staker/babylonclient"
	scfg "github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

type StakerApp struct {
	babylonClient cl.BabylonClient
	wc            walletcontroller.WalletController
	network       *chaincfg.Params
}

func (app *StakerApp) Start() {
	panic("implement me")
}

func (app *StakerApp) Stop() {
	panic("implement me")
}

func NewStakerAppFromConfig(config *scfg.Config) (*StakerApp, error) {
	// TODO: If we want to support multiple wallet types, this is most probably the place to decide
	// on concrete implementation
	walletClient, err := walletcontroller.NewRpcWalletController(config)
	if err != nil {
		return nil, err
	}

	// TODO use real client
	cl := cl.GetMockClient()

	return &StakerApp{
		babylonClient: cl,
		wc:            walletClient,
		network:       &config.ActiveNetParams,
	}, nil
}

func (app *StakerApp) Wallet() walletcontroller.WalletController {
	return app.wc
}

func (app *StakerApp) StakeFunds(
	stakerAddress btcutil.Address,
	stakingAmount btcutil.Amount,
	delegatorPk *btcec.PublicKey,
	stakingTimeBlocks uint16,
) error {
	params, err := app.babylonClient.Params()

	if err != nil {
		return err
	}

	if stakingAmount < params.MinSlashingTxFeeSat {
		return fmt.Errorf("staking amount %d is less than minimum slashing fee %d",
			stakingAmount, params.MinSlashingTxFeeSat)
	}

	if uint32(stakingTimeBlocks) < params.MinmumStakingTimeBlocks {
		return fmt.Errorf("staking time %d is less than minimum staking time %d",
			stakingTimeBlocks, params.MinmumStakingTimeBlocks)
	}

	// unlock wallet for the rest of the operations
	// TODOconsider unlock/lock with defer
	err = app.wc.UnlockWallet(15)
	if err != nil {
		return err
	}

	stakerKey, err := app.wc.AddressPublicKey(stakerAddress)

	if err != nil {
		return err
	}

	ouput, _, err := staking.BuildStakingOutput(
		stakerKey,
		delegatorPk,
		&params.JuryPk,
		stakingTimeBlocks,
		stakingAmount,
		app.network,
	)

	if err != nil {
		return err
	}

	tx, err := app.wc.CreateAndSignTx([]*wire.TxOut{ouput}, 100, stakerAddress)

	if err != nil {
		return err
	}

	_, err = app.wc.SendRawTransaction(tx, true)

	if err != nil {
		return err
	}

	return nil
}
