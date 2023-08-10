package stakerdb

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/babylonchain/btc-staker/proto"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	pm "google.golang.org/protobuf/proto"

	"github.com/lightningnetwork/lnd/kvdb"
)

var (
	// mapping uint64 -> proto.TrackedTransaction
	transactionBucketName = []byte("transactions")

	// mapping txHash -> uint64
	transactionIndexName = []byte("transactionIdx")

	// key for next transaction
	numTxKey = []byte("ntk")
)

type TrackedTransactionStore struct {
	db kvdb.Backend
}

type ProofOfPossession struct {
	BabylonSigOverBtcPk         []byte
	BtcSchnorrSigOverBabylonSig []byte
}

func NewProofOfPossession(
	babylonSigOverBtcPk []byte,
	btcSchnorrSigOverBabylonSig []byte,
) *ProofOfPossession {
	return &ProofOfPossession{
		BabylonSigOverBtcPk:         babylonSigOverBtcPk,
		BtcSchnorrSigOverBabylonSig: btcSchnorrSigOverBabylonSig,
	}
}

type StoredTransaction struct {
	BtcTx              *wire.MsgTx
	StakingOutputIndex uint32
	TxScript           []byte
	Pop                *ProofOfPossession
	// Returning address as string, to avoid having to know how to decode address
	// which requires knowing the network we are on
	StakerAddress string
	State         proto.TransactionState
}

type StoredTransactionQuery struct {
	IndexOffset uint64

	NumMaxTransactions uint64

	Reversed bool
}

func DefaultStoredTransactionQuery() StoredTransactionQuery {
	return StoredTransactionQuery{
		IndexOffset:        0,
		NumMaxTransactions: 50,
		Reversed:           false,
	}
}

type StoredTransactionQueryResult struct {
	Transactions []StoredTransaction
	Total        uint64
}

// NewTrackedTransactionStore returns a new store backed by db
func NewTrackedTransactionStore(db kvdb.Backend) (*TrackedTransactionStore,
	error) {

	store := &TrackedTransactionStore{db}
	if err := store.initBuckets(); err != nil {
		return nil, err
	}

	return store, nil
}

func (c *TrackedTransactionStore) initBuckets() error {
	return kvdb.Batch(c.db, func(tx kvdb.RwTx) error {
		_, err := tx.CreateTopLevelBucket(transactionBucketName)
		if err != nil {
			return err
		}

		_, err = tx.CreateTopLevelBucket(transactionIndexName)
		if err != nil {
			return err
		}
		return nil
	})
}

func protoTxToStoredTransaction(ttx *proto.TrackedTransaction) (*StoredTransaction, error) {
	var stakingTx wire.MsgTx
	err := stakingTx.Deserialize(bytes.NewReader(ttx.StakingTransaction))

	if err != nil {
		return nil, err
	}

	return &StoredTransaction{
		BtcTx:              &stakingTx,
		StakingOutputIndex: ttx.StakingOutputIdx,
		TxScript:           ttx.StakingScript,
		Pop: &ProofOfPossession{
			BabylonSigOverBtcPk:         ttx.BabylonSigBtcPk,
			BtcSchnorrSigOverBabylonSig: ttx.SchnorSigBabylonSig,
		},
		StakerAddress: ttx.StakerAddress,
		State:         ttx.State,
	}, nil
}

func uint64KeyToBytes(key uint64) []byte {
	var keyBytes = make([]byte, 8)
	binary.BigEndian.PutUint64(keyBytes, key)
	return keyBytes
}

func nextTxKey(txIdxBucket walletdb.ReadBucket) uint64 {
	numTxBytes := txIdxBucket.Get(numTxKey)
	var currKey uint64
	if numTxBytes == nil {
		currKey = 1
	} else {
		currKey = binary.BigEndian.Uint64(numTxBytes)
	}

	return currKey
}

func getNumTx(txIdxBucket walletdb.ReadBucket) uint64 {
	// we are starting indexing transactions from 1, and nextTxKey always return next key
	// which should be used when indexing transaction, so to get number of transactions
	// we need to subtract 1
	return nextTxKey(txIdxBucket) - 1
}

// getTxByHash retruns transaction and transaction key if transaction with given hash exsits
func getTxByHash(
	txHashBytes []byte,
	txIndexBucket walletdb.ReadBucket,
	txBucket walletdb.ReadBucket) ([]byte, []byte, error) {
	txKey := txIndexBucket.Get(txHashBytes)

	if txKey == nil {
		return nil, nil, ErrTransactionNotFound
	}

	maybeTx := txBucket.Get(txKey)

	if maybeTx == nil {
		// if we have index, but do not have transaction, it means something weird happened
		// and we have corrupted db
		return nil, nil, ErrCorruptedTransactionsDb
	}

	return maybeTx, txKey, nil
}

func saveTrackedTransaction(
	txIdxBucket walletdb.ReadWriteBucket,
	txBucket walletdb.ReadWriteBucket,
	txHashBytes []byte,
	tx *proto.TrackedTransaction) error {

	marshalled, err := pm.Marshal(tx)

	if err != nil {
		return err
	}

	nextTxKey := nextTxKey(txIdxBucket)

	nextTxKeyBytes := uint64KeyToBytes(nextTxKey)

	err = txBucket.Put(nextTxKeyBytes, marshalled)

	if err != nil {
		return err
	}

	err = txIdxBucket.Put(txHashBytes, nextTxKeyBytes)

	if err != nil {
		return err
	}

	// increment counter for the next transaction
	return txIdxBucket.Put(numTxKey, uint64KeyToBytes(nextTxKey+1))
}

func (c *TrackedTransactionStore) AddTransaction(
	btcTx *wire.MsgTx,
	stakingOutputIndex uint32,
	txscript []byte,
	pop *ProofOfPossession,
	stakerAddress btcutil.Address,
) error {
	txHash := btcTx.TxHash()
	txHashBytes := txHash[:]
	serializedTx, err := utils.SerializeBtcTransaction(btcTx)

	if err != nil {
		return err
	}

	return kvdb.Batch(c.db, func(tx kvdb.RwTx) error {
		transactionsBucketIdxBucket := tx.ReadWriteBucket(transactionIndexName)

		if transactionsBucketIdxBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		// check index first to avoid duplicates
		maybeTx := transactionsBucketIdxBucket.Get(txHashBytes)
		if maybeTx != nil {
			return ErrDuplicateTransaction
		}

		transactionsBucket := tx.ReadWriteBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		msg := proto.TrackedTransaction{
			StakingTransaction:  serializedTx,
			StakingScript:       txscript,
			StakingOutputIdx:    stakingOutputIndex,
			StakerAddress:       stakerAddress.EncodeAddress(),
			BabylonSigBtcPk:     pop.BabylonSigOverBtcPk,
			SchnorSigBabylonSig: pop.BtcSchnorrSigOverBabylonSig,
			State:               proto.TransactionState_SENT_TO_BTC,
		}

		return saveTrackedTransaction(transactionsBucketIdxBucket, transactionsBucket, txHashBytes, &msg)
	})
}

func (c *TrackedTransactionStore) setTxState(txHash *chainhash.Hash, state proto.TransactionState) error {
	txHashBytes := txHash.CloneBytes()

	return kvdb.Batch(c.db, func(tx kvdb.RwTx) error {
		transactionIdxBucket := tx.ReadWriteBucket(transactionIndexName)

		if transactionIdxBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		transactionsBucket := tx.ReadWriteBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		maybeTx, txKey, err := getTxByHash(txHashBytes, transactionIdxBucket, transactionsBucket)

		if err != nil {
			return err
		}

		var storedTx proto.TrackedTransaction
		err = pm.Unmarshal(maybeTx, &storedTx)
		if err != nil {
			return ErrCorruptedTransactionsDb
		}

		storedTx.State = state

		marshalled, err := pm.Marshal(&storedTx)

		if err != nil {
			return err
		}

		return transactionsBucket.Put(txKey, marshalled)
	})
}

func (c *TrackedTransactionStore) SetTxConfirmed(txHash *chainhash.Hash) error {
	return c.setTxState(txHash, proto.TransactionState_CONFIRMED_ON_BTC)
}

func (c *TrackedTransactionStore) SetTxSentToBabylon(txHash *chainhash.Hash) error {
	return c.setTxState(txHash, proto.TransactionState_SENT_TO_BABYLON)
}

func (c *TrackedTransactionStore) SetTxSpentOnBtc(txHash *chainhash.Hash) error {
	return c.setTxState(txHash, proto.TransactionState_SPENT_ON_BTC)
}

func (c *TrackedTransactionStore) GetTransaction(txHash *chainhash.Hash) (*StoredTransaction, error) {
	var storedTx *StoredTransaction
	txHashBytes := txHash.CloneBytes()

	err := c.db.View(func(tx kvdb.RTx) error {
		transactionIdxBucket := tx.ReadBucket(transactionIndexName)

		if transactionIdxBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		transactionsBucket := tx.ReadBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		maybeTx, _, err := getTxByHash(txHashBytes, transactionIdxBucket, transactionsBucket)

		if err != nil {
			return err
		}

		var storedTxProto proto.TrackedTransaction
		err = pm.Unmarshal(maybeTx, &storedTxProto)

		if err != nil {
			return ErrCorruptedTransactionsDb
		}

		txFromDb, err := protoTxToStoredTransaction(&storedTxProto)

		if err != nil {
			return err
		}

		storedTx = txFromDb
		return nil
	}, func() {})

	if err != nil {
		return nil, err
	}

	return storedTx, nil
}

func (c *TrackedTransactionStore) GetAllStoredTransactions() ([]StoredTransaction, error) {
	q := DefaultStoredTransactionQuery()
	// MaxUint64 indicates we will scan over all transactions
	q.NumMaxTransactions = math.MaxUint64

	resp, err := c.QueryStoredTransactions(q)
	if err != nil {
		return nil, err
	}

	return resp.Transactions, nil
}

func (c *TrackedTransactionStore) QueryStoredTransactions(q StoredTransactionQuery) (StoredTransactionQueryResult, error) {
	var resp StoredTransactionQueryResult

	err := c.db.View(func(tx kvdb.RTx) error {
		transactionsBucket := tx.ReadBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		transactionIdxBucket := tx.ReadBucket(transactionIndexName)

		if transactionIdxBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		numTransactions := getNumTx(transactionIdxBucket)

		if numTransactions == 0 {
			return nil
		}

		resp.Total = numTransactions

		paginator := newPaginator(
			transactionsBucket.ReadCursor(), q.Reversed, q.IndexOffset,
			q.NumMaxTransactions,
		)

		accumulateTransactions := func(key, transaction []byte) (bool, error) {
			protoTx := proto.TrackedTransaction{}

			err := pm.Unmarshal(transaction, &protoTx)
			if err != nil {
				return false, err
			}

			txFromDb, err := protoTxToStoredTransaction(&protoTx)

			if err != nil {
				return false, err
			}

			// TODO: Add filtering by state ? (e.g. only confirmed transactions)

			resp.Transactions = append(resp.Transactions, *txFromDb)
			return true, nil
		}

		if err := paginator.query(accumulateTransactions); err != nil {
			return err
		}

		if q.Reversed {
			numTx := len(resp.Transactions)
			for i := 0; i < numTx/2; i++ {
				reverse := numTx - i - 1
				resp.Transactions[i], resp.Transactions[reverse] =
					resp.Transactions[reverse], resp.Transactions[i]
			}
		}

		return nil
	}, func() {
		resp = StoredTransactionQueryResult{}
	})

	if err != nil {
		return resp, err
	}

	return resp, nil
}
