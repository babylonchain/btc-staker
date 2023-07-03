package walletcontroller

import (
	"sort"

	"github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type RpcWalletController struct {
	*rpcclient.Client
	walletPassphrase string
	network          string
}

var _ WalletController = (*RpcWalletController)(nil)

func NewRpcWalletController(scfg *stakercfg.StakerConfig) (*RpcWalletController, error) {
	return NewRpcWalletControllerFromArgs(
		scfg.WalletRpcConfig.Host,
		scfg.WalletRpcConfig.User,
		scfg.WalletRpcConfig.Pass,
		scfg.ChainConfig.Network,
		scfg.WalletConfig.WalletPass,
		// TODO for now just disable tls
		true,
	)
}

func NewRpcWalletControllerFromArgs(
	host string,
	user string,
	pass string,
	network string,
	walletPassphrase string,
	disableTls bool,
) (*RpcWalletController, error) {

	params, err := utils.GetBtcNetworkParams(network)

	if err != nil {
		return nil, err
	}

	connCfg := &rpcclient.ConnConfig{
		Host:       host,
		User:       user,
		Pass:       pass,
		Params:     network,
		DisableTLS: disableTls,

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

	return &RpcWalletController{
		Client:           rpcclient,
		walletPassphrase: walletPassphrase,
		network:          params.Name,
	}, nil
}

func (w *RpcWalletController) UnlockWallet(timoutSec int64) error {
	return w.WalletPassphrase(w.walletPassphrase, timoutSec)
}

func (w *RpcWalletController) AddressPublicKey(address btcutil.Address) (*btcec.PublicKey, error) {
	privKey, err := w.DumpPrivKey(address)

	if err != nil {
		return nil, err
	}

	return privKey.PrivKey.PubKey(), nil
}

func (w *RpcWalletController) NetworkName() string {
	return w.network
}

func (w *RpcWalletController) CreateTransaction(
	outputs []*wire.TxOut,
	feeRatePerKb btcutil.Amount,
	changeAddres btcutil.Address) (*wire.MsgTx, error) {

	utxoResults, err := w.ListUnspent()

	if err != nil {
		return nil, err
	}

	utxos, err := resultsToUtxos(utxoResults, true)

	if err != nil {
		return nil, err
	}

	// sort utxos by amount from highest to lowest, this is effectively strategy of using
	// largest inputs first
	sort.Sort(sort.Reverse(byAmount(utxos)))

	changeScript, err := txscript.PayToAddrScript(changeAddres)

	if err != nil {
		return nil, err
	}

	tx, err := buildTxFromOutputs(utxos, outputs, feeRatePerKb, changeScript)

	if err != nil {
		return nil, err
	}

	return tx, err
}

func (w *RpcWalletController) SignRawTransaction(tx *wire.MsgTx) (*wire.MsgTx, bool, error) {
	return w.Client.SignRawTransaction(tx)
}

func (w *RpcWalletController) SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (*chainhash.Hash, error) {
	return w.Client.SendRawTransaction(tx, allowHighFees)
}

func (w *RpcWalletController) ListOutputs(onlySpendable bool) ([]Utxo, error) {
	utxoResults, err := w.ListUnspent()

	if err != nil {
		return nil, err
	}

	utxos, err := resultsToUtxos(utxoResults, onlySpendable)

	if err != nil {
		return nil, err
	}

	return utxos, nil
}
