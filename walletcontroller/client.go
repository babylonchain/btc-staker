package walletcontroller

import (
	"fmt"
	"sort"

	"github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	notifier "github.com/lightningnetwork/lnd/chainntnfs"
)

type RpcWalletController struct {
	*rpcclient.Client
	walletPassphrase string
	network          string
	backend          types.SupportedWalletBackend
}

var _ WalletController = (*RpcWalletController)(nil)

const (
	txNotFoundErrMsgBtcd     = "No information available about transaction"
	txNotFoundErrMsgBitcoind = "No such mempool or blockchain transaction"
)

func NewRpcWalletController(scfg *stakercfg.Config) (*RpcWalletController, error) {
	return NewRpcWalletControllerFromArgs(
		scfg.WalletRpcConfig.Host,
		scfg.WalletRpcConfig.User,
		scfg.WalletRpcConfig.Pass,
		scfg.ActiveNetParams.Name,
		scfg.WalletConfig.WalletPass,
		scfg.BtcNodeBackendConfig.ActiveWalletBackend,
		&scfg.ActiveNetParams,
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
	nodeBackend types.SupportedWalletBackend,
	params *chaincfg.Params,
	disableTls bool,
) (*RpcWalletController, error) {

	connCfg := &rpcclient.ConnConfig{
		Host:                 host,
		User:                 user,
		Pass:                 pass,
		DisableTLS:           disableTls,
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
		backend:          nodeBackend,
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

func (w *RpcWalletController) DumpPrivateKey(address btcutil.Address) (*btcec.PrivateKey, error) {
	privKey, err := w.DumpPrivKey(address)

	if err != nil {
		return nil, err
	}

	return privKey.PrivKey, nil
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

func (w *RpcWalletController) CreateAndSignTx(
	outputs []*wire.TxOut,
	feeRatePerKb btcutil.Amount,
	changeAddress btcutil.Address,
) (*wire.MsgTx, error) {
	tx, err := w.CreateTransaction(outputs, feeRatePerKb, changeAddress)

	if err != nil {
		return nil, err
	}

	fundedTx, signed, err := w.SignRawTransaction(tx)

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

func (w *RpcWalletController) SignRawTransaction(tx *wire.MsgTx) (*wire.MsgTx, bool, error) {
	switch w.backend {
	case types.BitcoindWalletBackend:
		return w.Client.SignRawTransactionWithWallet(tx)
	case types.BtcwalletWalletBackend:
		return w.Client.SignRawTransaction(tx)
	default:
		return nil, false, fmt.Errorf("invalid bitcoin backend")
	}
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

func nofitierStateToWalletState(state notifier.TxConfStatus) TxStatus {
	switch state {
	case notifier.TxNotFoundIndex:
		return TxNotFound
	case notifier.TxFoundMempool:
		return TxInMemPool
	case notifier.TxFoundIndex:
		return TxInChain
	case notifier.TxNotFoundManually:
		return TxNotFound
	case notifier.TxFoundManually:
		return TxInChain
	default:
		panic(fmt.Sprintf("unknown notifier state: %s", state))
	}
}

func (w *RpcWalletController) getTxDetails(req notifier.ConfRequest, msg string) (*notifier.TxConfirmation, TxStatus, error) {
	res, state, err := notifier.ConfDetailsFromTxIndex(w.Client, req, msg)

	if err != nil {
		return nil, TxNotFound, err
	}

	return res, nofitierStateToWalletState(state), nil
}

// Fetch info about transaction from mempool or blockchain, requires node to have enabled  transaction index
func (w *RpcWalletController) TxDetails(txHash *chainhash.Hash, pkScript []byte) (*notifier.TxConfirmation, TxStatus, error) {
	req, err := notifier.NewConfRequest(txHash, pkScript)

	if err != nil {
		return nil, TxNotFound, err
	}

	switch w.backend {
	case types.BitcoindWalletBackend:
		return w.getTxDetails(req, txNotFoundErrMsgBitcoind)
	case types.BtcwalletWalletBackend:
		return w.getTxDetails(req, txNotFoundErrMsgBtcd)
	default:
		return nil, TxNotFound, fmt.Errorf("invalid bitcoin backend")
	}
}
