package staker

import (
	"bytes"
	"encoding/hex"
	"fmt"

	staking "github.com/babylonchain/babylon/btcstaking"
	scfg "github.com/babylonchain/btc-staker/stakercfg"
	ut "github.com/babylonchain/btc-staker/utils"
	"github.com/babylonchain/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type StakerApp struct {
	wc      walletcontroller.WalletController
	network *chaincfg.Params
}

type SlashingTxDescription struct {
	SlashingTx          *wire.MsgTx
	SlashingTxSignature *schnorr.Signature
}

func NewStakerAppFromConfig(config *scfg.Config) (*StakerApp, error) {
	// TODO: If we want to support multiple wallet types, this is most probably the place to decide
	// on concrete implementation
	walletClient, err := walletcontroller.NewRpcWalletController(config)
	if err != nil {
		return nil, err
	}

	return &StakerApp{
		wc:      walletClient,
		network: &config.ActiveNetParams,
	}, nil
}

func NewStakerAppFromClient(
	wc walletcontroller.WalletController) (*StakerApp, error) {

	networkName := wc.NetworkName()

	params, err := ut.GetBtcNetworkParams(networkName)

	if err != nil {
		return nil, err
	}

	return &StakerApp{
		wc:      wc,
		network: params,
	}, err
}

func buildStakingOutputFromScriptAndStakerKey(
	stakingScript []byte,
	stakerKey *btcec.PublicKey,
	stakingAmount int64,
	netParams *chaincfg.Params,
) (*wire.TxOut, error) {
	parsedScript, err := staking.ParseStakingTransactionScript(stakingScript)

	if err != nil {
		return nil, err
	}

	if !bytes.Equal(schnorr.SerializePubKey(stakerKey), schnorr.SerializePubKey(parsedScript.StakerKey)) {
		return nil, fmt.Errorf("staker key in staking script does not match staker key provided")
	}

	pkScript, err := staking.BuildUnspendableTaprootPkScript(stakingScript, netParams)

	if err != nil {
		return nil, err
	}

	return wire.NewTxOut(int64(stakingAmount), pkScript), nil
}

func (app *StakerApp) Wallet() walletcontroller.WalletController {
	return app.wc
}

func (app *StakerApp) CreateStakingTransactionFromArgs(
	stakerAddress string,
	stakingScript string,
	stakingAmount int64) (*wire.MsgTx, error) {
	stakerAddr, err := btcutil.DecodeAddress(stakerAddress, app.network)
	if err != nil {
		return nil, err
	}

	stakingScriptBytes, err := hex.DecodeString(stakingScript)
	if err != nil {
		return nil, err
	}

	return app.CreateStakingTransaction(stakerAddr, stakingScriptBytes, stakingAmount)
}

func (app *StakerApp) CreateStakingTransaction(
	stakerAddress btcutil.Address,
	stakingScript []byte,
	stakingAmount int64,
) (*wire.MsgTx, error) {
	if stakingAmount <= 0 {
		return nil, fmt.Errorf("staking amount must be positive")
	}

	// TODO: Parametrize unlocking timeout
	err := app.wc.UnlockWallet(15)
	if err != nil {
		return nil, err
	}

	stakerKey, err := app.wc.AddressPublicKey(stakerAddress)

	if nil != err {
		return nil, err
	}

	output, err := buildStakingOutputFromScriptAndStakerKey(
		stakingScript,
		stakerKey,
		stakingAmount,
		app.network,
	)

	if err != nil {
		return nil, err
	}

	// Return change to staker address
	// TODO: Change address should either provided by user or fresh new change address
	// should be fetched by wallet controller
	// TODO: Fee also should be provided by user or estimated
	tx, err := app.wc.CreateTransaction([]*wire.TxOut{output}, 100, stakerAddress)

	if err != nil {
		return nil, err
	}

	fundedTx, signed, err := app.wc.SignRawTransaction(tx)

	if err != nil {
		return nil, err
	}

	if !signed {
		// TODO: Investigate this case a bit more thoroughly, to check if we can recover
		// somehow
		return nil, fmt.Errorf("not all transactions inputs could be signed")
	}

	return fundedTx, nil
}

func (app *StakerApp) SendStakingTransaction(
	stakerAddress btcutil.Address,
	stakingScript []byte,
	stakingAmount int64,
) (*wire.MsgTx, *chainhash.Hash, error) {
	tx, err := app.CreateStakingTransaction(stakerAddress, stakingScript, stakingAmount)
	if err != nil {
		return nil, nil, err
	}

	txHash, err := app.wc.SendRawTransaction(tx, true)

	if err != nil {
		return nil, nil, err
	}

	return tx, txHash, nil
}

func (app *StakerApp) SendStakingTransactionFromArgs(
	stakerAddress string,
	stakingScript string,
	stakingAmount int64) (*wire.MsgTx, *chainhash.Hash, error) {
	tx, err := app.CreateStakingTransactionFromArgs(stakerAddress, stakingScript, stakingAmount)
	if err != nil {
		return nil, nil, err
	}

	txHash, err := app.wc.SendRawTransaction(tx, true)

	if err != nil {
		return nil, nil, err
	}

	return tx, txHash, nil

}
