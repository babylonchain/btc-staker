package walletcontroller

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
)

type Utxo struct {
	Amount       btcutil.Amount
	OutPoint     wire.OutPoint
	PkScript     []byte
	RedeemScript []byte
	Address      string
}

type byAmount []Utxo

func (s byAmount) Len() int           { return len(s) }
func (s byAmount) Less(i, j int) bool { return s[i].Amount < s[j].Amount }
func (s byAmount) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

func resultsToUtxos(results []btcjson.ListUnspentResult, onlySpendable bool) ([]Utxo, error) {
	var utxos []Utxo
	for _, result := range results {
		if onlySpendable && !result.Spendable {
			// skip unspendable outputs
			continue
		}

		amount, err := btcutil.NewAmount(result.Amount)

		if err != nil {
			return nil, err
		}

		chainhash, err := chainhash.NewHashFromStr(result.TxID)

		if err != nil {
			return nil, err
		}

		outpoint := wire.NewOutPoint(chainhash, result.Vout)

		script, err := hex.DecodeString(result.ScriptPubKey)

		if err != nil {
			return nil, err
		}

		redeemScript, err := hex.DecodeString(result.RedeemScript)

		if err != nil {
			return nil, err
		}

		utxo := Utxo{
			Amount:       amount,
			OutPoint:     *outpoint,
			PkScript:     script,
			RedeemScript: redeemScript,
			Address:      result.Address,
		}
		utxos = append(utxos, utxo)
	}
	return utxos, nil
}

func makeInputSource(utxos []Utxo) txauthor.InputSource {
	currentTotal := btcutil.Amount(0)
	currentInputs := make([]*wire.TxIn, 0, len(utxos))
	currentScripts := make([][]byte, 0, len(utxos))
	currentInputValues := make([]btcutil.Amount, 0, len(utxos))

	return func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
		[]btcutil.Amount, [][]byte, error) {

		for currentTotal < target && len(utxos) != 0 {
			nextCredit := &utxos[0]
			utxos = utxos[1:]
			nextInput := wire.NewTxIn(&nextCredit.OutPoint, nil, nil)
			currentTotal += nextCredit.Amount
			currentInputs = append(currentInputs, nextInput)
			currentScripts = append(currentScripts, nextCredit.PkScript)
			currentInputValues = append(currentInputValues, nextCredit.Amount)
		}
		return currentTotal, currentInputs, currentInputValues, currentScripts, nil
	}
}

func buildTxFromOutputs(
	utxos []Utxo,
	outputs []*wire.TxOut,
	feeRatePerKb btcutil.Amount,
	changeScript []byte) (*wire.MsgTx, error) {

	if len(utxos) == 0 {
		return nil, fmt.Errorf("there must be at least 1 usable UTXO to build transaction")
	}

	if len(outputs) == 0 {
		return nil, fmt.Errorf("there must be at least 1 output in transaction")
	}

	ch := txauthor.ChangeSource{
		NewScript: func() ([]byte, error) {
			return changeScript, nil
		},
		ScriptSize: len(changeScript),
	}

	inputSource := makeInputSource(utxos)

	authoredTx, err := txauthor.NewUnsignedTransaction(
		outputs,
		feeRatePerKb,
		inputSource,
		&ch,
	)

	if err != nil {
		return nil, err
	}

	return authoredTx.Tx, nil
}
