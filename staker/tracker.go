package staker

import (
	"fmt"

	"github.com/btcsuite/btcd/wire"
)

type TxState uint8

const (
	Send TxState = iota
	Confirmed
)

type TrackedTransaction struct {
	tx *wire.MsgTx
	// We need to track script also, as it is needed for slashing tx buidling
	txscript []byte

	state TxState
}

// TODO Add version with db!
// Not thread safe!
type StakingTxTracker struct {
	transactions map[string]*TrackedTransaction
}

func NewStakingTxTracker() *StakingTxTracker {
	return &StakingTxTracker{
		transactions: make(map[string]*TrackedTransaction),
	}
}

func (t *StakingTxTracker) Add(tx *wire.MsgTx, txscript []byte) error {
	txHash := tx.TxHash().String()

	_, ok := t.transactions[txHash]

	if ok {
		return fmt.Errorf("tx with hash %s already added", txHash)
	}

	t.transactions[txHash] = &TrackedTransaction{
		tx:       tx,
		txscript: txscript,
		state:    Send,
	}

	return nil
}

// returns nil only if tx is not found
func (t *StakingTxTracker) Get(txHash string) *TrackedTransaction {
	entry, ok := t.transactions[txHash]

	if !ok {
		return nil
	}

	return entry
}

func (t *StakingTxTracker) Remove(txHash string) {
	delete(t.transactions, txHash)
}
