package stakerdb

import (
	"bytes"

	"github.com/babylonchain/btc-staker/proto"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	pm "google.golang.org/protobuf/proto"

	"github.com/lightningnetwork/lnd/kvdb"
)

var (
	transactionBucketName = []byte("transactions")
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

func (c *TrackedTransactionStore) AddTransaction(
	btcTx *wire.MsgTx,
	stakingOutputIndex uint32,
	txscript []byte,
	pop *ProofOfPossession,
	stakerAddress btcutil.Address,
) error {
	txHash := btcTx.TxHash()
	txHashBytes := txHash[:]

	return kvdb.Batch(c.db, func(tx kvdb.RwTx) error {
		transactionsBucket := tx.ReadWriteBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		maybeTx := transactionsBucket.Get(txHashBytes)
		if maybeTx != nil {
			return ErrDuplicateTransaction
		}

		serializedTx, err := utils.SerializeBtcTransaction(btcTx)

		if err != nil {
			return err
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

		marshalled, err := pm.Marshal(&msg)

		if err != nil {
			return err
		}

		return transactionsBucket.Put(txHashBytes, marshalled)
	})
}

func (c *TrackedTransactionStore) setTxState(txHash *chainhash.Hash, state proto.TransactionState) error {
	txHashBytes := txHash.CloneBytes()

	return kvdb.Batch(c.db, func(tx kvdb.RwTx) error {
		transactionsBucket := tx.ReadWriteBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		maybeTx := transactionsBucket.Get(txHashBytes)
		if maybeTx == nil {
			return ErrTransactionNotFound
		}

		var storedTx proto.TrackedTransaction
		err := pm.Unmarshal(maybeTx, &storedTx)
		if err != nil {
			return ErrCorruptedTransactionsDb
		}

		storedTx.State = state

		marshalled, err := pm.Marshal(&storedTx)

		if err != nil {
			return err
		}

		return transactionsBucket.Put(txHashBytes, marshalled)
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
	err := c.db.View(func(tx kvdb.RTx) error {
		transactionsBucket := tx.ReadBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		maybeTx := transactionsBucket.Get(txHash.CloneBytes())

		if maybeTx == nil {
			return ErrTransactionNotFound
		}

		var storedTxProto proto.TrackedTransaction
		err := pm.Unmarshal(maybeTx, &storedTxProto)

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

func (c *TrackedTransactionStore) GetAllStoredTransactions() ([]*StoredTransaction, error) {
	var storedTx []*StoredTransaction
	err := c.db.View(func(tx kvdb.RTx) error {
		transactionsBucket := tx.ReadBucket(transactionBucketName)
		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		return transactionsBucket.ForEach(func(k, v []byte) error {
			protoTx := proto.TrackedTransaction{}

			err := pm.Unmarshal(v, &protoTx)
			if err != nil {
				return err
			}

			txFromDb, err := protoTxToStoredTransaction(&protoTx)

			if err != nil {
				return err
			}

			storedTx = append(storedTx, txFromDb)
			return nil
		})
	}, func() {})

	if err != nil {
		return nil, err
	}

	return storedTx, nil
}
