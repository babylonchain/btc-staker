package walletclient

import (
	"github.com/babylonchain/btc-staker/stakercfg"
	"github.com/btcsuite/btcd/rpcclient"
)

type WalletClient struct {
	*rpcclient.Client
}

func NewWalletClient(scfg *stakercfg.StakerConfig) (*WalletClient, error) {
	connCfg := &rpcclient.ConnConfig{
		Host: scfg.WalletRpcConfig.Host,
		User: scfg.WalletRpcConfig.User,
		Pass: scfg.WalletRpcConfig.Pass,
		// TODO: For now just disable tls
		DisableTLS:           true,
		Params:               scfg.ChainConfig.Network,
		DisableConnectOnNew:  true,
		DisableAutoReconnect: false,
		// we use post mode as it sure it works with either bitcoind or btcwallet
		// we may need to re-consider it later if we need any notifications
		HTTPPostMode: true,
	}

	rpcclient, err := rpcclient.New(connCfg, nil)

	if err != nil {
		return nil, err
	}

	return &WalletClient{
		Client: rpcclient,
	}, err
}
