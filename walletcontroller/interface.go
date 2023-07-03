package walletcontroller

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type WalletController interface {
	UnlockWallet(timeoutSecs int64) error
	AddressPublicKey(address btcutil.Address) (*btcec.PublicKey, error)
	NetworkName() string
	CreateTransaction(
		outputs []*wire.TxOut,
		feeRatePerKb btcutil.Amount,
		changeScript btcutil.Address) (*wire.MsgTx, error)
	SignRawTransaction(tx *wire.MsgTx) (*wire.MsgTx, bool, error)
	SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (*chainhash.Hash, error)
	ListOutputs(onlySpendable bool) ([]Utxo, error)
}
