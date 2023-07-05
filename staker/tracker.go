package staker

import "github.com/btcsuite/btcd/wire"

type TrackedTransaction struct {
	tx *wire.MsgTx
	// We need to track script also, as it is needed for slashing tx buidling
	txscript []byte
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

func (t *StakingTxTracker) Add(tx *wire.MsgTx, txscript []byte) {
	t.transactions[tx.TxHash().String()] = &TrackedTransaction{
		tx:       tx,
		txscript: txscript,
	}
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
