package staker

import (
	cl "github.com/babylonchain/btc-staker/babylonclient"
	ut "github.com/babylonchain/btc-staker/utils"
	"github.com/babylonchain/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/chaincfg"
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
