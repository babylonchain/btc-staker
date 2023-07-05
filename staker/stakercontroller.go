package staker

import (
	"encoding/hex"
	"fmt"

	cl "github.com/babylonchain/btc-staker/babylonclient"
	ut "github.com/babylonchain/btc-staker/utils"
	"github.com/babylonchain/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// Stateless controller for different client operations
type StakerController struct {
	BabylonClient cl.BabylonClient
	Wc            walletcontroller.WalletController
	network       *chaincfg.Params
}

func NewStakerControllerFromClients(
	wc walletcontroller.WalletController,
	BabylonClient cl.BabylonClient,
) (*StakerController, error) {

	networkName := wc.NetworkName()

	params, err := ut.GetBtcNetworkParams(networkName)

	if err != nil {
		return nil, err
	}

	return &StakerController{
		Wc:            wc,
		network:       params,
		BabylonClient: BabylonClient,
	}, err
}

func (sc *StakerController) CreateStakingTransactionFromArgs(
	stakerAddress string,
	stakingScript string,
	stakingAmount int64) (*wire.MsgTx, error) {
	stakerAddr, err := btcutil.DecodeAddress(stakerAddress, sc.network)
	if err != nil {
		return nil, err
	}

	stakingScriptBytes, err := hex.DecodeString(stakingScript)
	if err != nil {
		return nil, err
	}

	return sc.CreateStakingTransaction(stakerAddr, stakingScriptBytes, stakingAmount)
}

func (sc *StakerController) CreateStakingTransaction(
	stakerAddress btcutil.Address,
	stakingScript []byte,
	stakingAmount int64,
) (*wire.MsgTx, error) {
	if stakingAmount <= 0 {
		return nil, fmt.Errorf("staking amount must be positive")
	}

	// TODO: Parametrize unlocking timeout
	err := sc.Wc.UnlockWallet(15)
	if err != nil {
		return nil, err
	}

	stakerKey, err := sc.Wc.AddressPublicKey(stakerAddress)

	if nil != err {
		return nil, err
	}

	output, err := BuildStakingOutputFromScriptAndStakerKey(
		stakingScript,
		stakerKey,
		stakingAmount,
		sc.network,
	)

	if err != nil {
		return nil, err
	}

	// Return change to staker address
	// TODO: Change address should either provided by user or fresh new change address
	// should be fetched by wallet controller
	// TODO: Fee also should be provided by user or estimated
	tx, err := sc.Wc.CreateAndSignTx([]*wire.TxOut{output}, 100, stakerAddress)

	if err != nil {
		return nil, err
	}

	return tx, nil
}

func (sc *StakerController) SendStakingTransaction(
	stakerAddress btcutil.Address,
	stakingScript []byte,
	stakingAmount int64,
) (*wire.MsgTx, *chainhash.Hash, error) {
	tx, err := sc.CreateStakingTransaction(stakerAddress, stakingScript, stakingAmount)
	if err != nil {
		return nil, nil, err
	}

	txHash, err := sc.Wc.SendRawTransaction(tx, true)

	if err != nil {
		return nil, nil, err
	}

	return tx, txHash, nil
}

func (sc *StakerController) SendStakingTransactionFromArgs(
	stakerAddress string,
	stakingScript string,
	stakingAmount int64) (*wire.MsgTx, *chainhash.Hash, error) {
	tx, err := sc.CreateStakingTransactionFromArgs(stakerAddress, stakingScript, stakingAmount)
	if err != nil {
		return nil, nil, err
	}

	txHash, err := sc.Wc.SendRawTransaction(tx, true)

	if err != nil {
		return nil, nil, err
	}

	return tx, txHash, nil
}
