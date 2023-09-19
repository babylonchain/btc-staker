package stakerdb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/babylonchain/btc-staker/proto"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	pm "google.golang.org/protobuf/proto"

	"github.com/lightningnetwork/lnd/kvdb"
)

var (
	// mapping uint64 -> proto.TrackedTransaction
	transactionBucketName = []byte("transactions")

	// mapping txHash -> uint64
	transactionIndexName = []byte("transactionIdx")

	// mapping txHash -> proto.WatchedData
	// It holds additional data for staking transaction in watch only mode
	watchedTxDataBucketName = []byte("watched")

	// key for next transaction
	numTxKey = []byte("ntk")
)

type StoredTransactionScanFn func(tx *StoredTransaction) error

type TrackedTransactionStore struct {
	db kvdb.Backend
}

type ProofOfPossession struct {
	BtcSigType           uint32
	BabylonSigOverBtcPk  []byte
	BtcSigOverBabylonSig []byte
}

func NewProofOfPossession(
	babylonSigOverBtcPk []byte,
	btcSchnorrSigOverBabylonSig []byte,
) *ProofOfPossession {
	return &ProofOfPossession{
		BabylonSigOverBtcPk:  babylonSigOverBtcPk,
		BtcSigOverBabylonSig: btcSchnorrSigOverBabylonSig,
	}
}

type StoredTransaction struct {
	BtcTx              *wire.MsgTx
	StakingOutputIndex uint32
	TxScript           []byte
	Pop                *ProofOfPossession
	// Returning address as string, to avoid having to know how to decode address
	// which requires knowing the network we are on
	StakerAddress   string
	State           proto.TransactionState
	Watched         bool
	UnbondingTxData *UnbondingStoreData
}

type WatchedTransactionData struct {
	SlashingTx          *wire.MsgTx
	SlashingTxSig       *schnorr.Signature
	StakerBabylonPubKey *secp256k1.PubKey
}

type UnbondingStoreData struct {
	UnbondingTx                   *wire.MsgTx
	UnbondingTxScript             []byte
	UnbondingTxValidatorSignature *schnorr.Signature
	UnbondingTxJurySignature      *schnorr.Signature
}

func newInitialUnbondingTxData(
	unbondingTx *wire.MsgTx,
	unbondingTxScript []byte,
) (*proto.UnbondingTxData, error) {
	if unbondingTx == nil {
		return nil, fmt.Errorf("cannot create unbonding tx data without unbonding tx")
	}

	if len(unbondingTxScript) == 0 {
		return nil, fmt.Errorf("cannot create unbonding tx data without unbonding tx script")
	}

	serializedTx, err := utils.SerializeBtcTransaction(unbondingTx)

	if err != nil {
		return nil, fmt.Errorf("cannot create unbonding tx data: %w", err)
	}

	unbondingData := &proto.UnbondingTxData{
		UnbondingTransaction:             serializedTx,
		UnbondingTransactionScript:       unbondingTxScript,
		UnbondingTransactionValidatorSig: nil,
		UnbondingTransactionJurySig:      nil,
	}

	return unbondingData, nil
}

func newUnbondingSignaturesUpdate(
	unbondingTxValidatorSignature *schnorr.Signature,
	unbondingTxJurySignature *schnorr.Signature,
) (*proto.UnbondingTxData, error) {
	if unbondingTxValidatorSignature == nil {
		return nil, fmt.Errorf("cannot create unbonding tx data without validator signature")
	}

	if unbondingTxJurySignature == nil {
		return nil, fmt.Errorf("cannot create unbonding tx data without jury signature")
	}

	unbondingData := &proto.UnbondingTxData{
		UnbondingTransaction:             nil,
		UnbondingTransactionScript:       nil,
		UnbondingTransactionValidatorSig: unbondingTxValidatorSignature.Serialize(),
		UnbondingTransactionJurySig:      unbondingTxJurySignature.Serialize(),
	}

	return unbondingData, nil
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

		_, err = tx.CreateTopLevelBucket(watchedTxDataBucketName)
		if err != nil {
			return err
		}

		return nil
	})
}

func protoUnbondingDataToUnbondingStoreData(ud *proto.UnbondingTxData) (*UnbondingStoreData, error) {
	// Unbodning txdata should always containt unbodning transaction and script
	var unbondingTx wire.MsgTx
	err := unbondingTx.Deserialize(bytes.NewReader(ud.UnbondingTransaction))

	if err != nil {
		return nil, err
	}

	var validatorSig *schnorr.Signature
	if ud.UnbondingTransactionValidatorSig != nil {
		validatorSig, err = schnorr.ParseSignature(ud.UnbondingTransactionValidatorSig)

		if err != nil {
			return nil, err
		}
	}

	var jurySig *schnorr.Signature
	if ud.UnbondingTransactionJurySig != nil {
		jurySig, err = schnorr.ParseSignature(ud.UnbondingTransactionJurySig)

		if err != nil {
			return nil, err
		}
	}

	return &UnbondingStoreData{
		UnbondingTx:                   &unbondingTx,
		UnbondingTxScript:             ud.UnbondingTransactionScript,
		UnbondingTxValidatorSignature: validatorSig,
		UnbondingTxJurySignature:      jurySig,
	}, nil
}

func protoTxToStoredTransaction(ttx *proto.TrackedTransaction) (*StoredTransaction, error) {
	var stakingTx wire.MsgTx
	err := stakingTx.Deserialize(bytes.NewReader(ttx.StakingTransaction))

	if err != nil {
		return nil, err
	}

	var utd *UnbondingStoreData = nil

	if ttx.UnbondingTxData != nil {
		unbondingData, err := protoUnbondingDataToUnbondingStoreData(ttx.UnbondingTxData)

		if err != nil {
			return nil, err
		}

		utd = unbondingData
	}

	return &StoredTransaction{
		BtcTx:              &stakingTx,
		StakingOutputIndex: ttx.StakingOutputIdx,
		TxScript:           ttx.StakingScript,
		Pop: &ProofOfPossession{
			BtcSigType:           ttx.BtcSigType,
			BabylonSigOverBtcPk:  ttx.BabylonSigBtcPk,
			BtcSigOverBabylonSig: ttx.BtcSigBabylonSig,
		},
		StakerAddress:   ttx.StakerAddress,
		State:           ttx.State,
		Watched:         ttx.Watched,
		UnbondingTxData: utd,
	}, nil
}

func protoWatchedDataToWatchedTransactionData(wd *proto.WatchedTxData) (*WatchedTransactionData, error) {
	var slashingTx wire.MsgTx
	err := slashingTx.Deserialize(bytes.NewReader(wd.SlashingTransaction))
	if err != nil {
		return nil, err
	}

	schnorSig, err := schnorr.ParseSignature(wd.SlashingTransactionSig)

	if err != nil {
		return nil, err
	}

	stakerBabylonKey := secp256k1.PubKey{
		Key: wd.StakerBabylonPk,
	}

	return &WatchedTransactionData{
		SlashingTx:          &slashingTx,
		SlashingTxSig:       schnorSig,
		StakerBabylonPubKey: &stakerBabylonKey,
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
	rwTx kvdb.RwTx,
	txIdxBucket walletdb.ReadWriteBucket,
	txBucket walletdb.ReadWriteBucket,
	txHashBytes []byte,
	tx *proto.TrackedTransaction,
	watchedTxData *proto.WatchedTxData,
) error {
	if tx == nil {
		return fmt.Errorf("cannot save nil tracked transaciton")
	}

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

	if watchedTxData != nil {
		watchedTxBucket := rwTx.ReadWriteBucket(watchedTxDataBucketName)
		if watchedTxBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		marshalled, err := pm.Marshal(watchedTxData)

		if err != nil {
			return err
		}

		err = watchedTxBucket.Put(txHashBytes, marshalled)

		if err != nil {
			return err
		}
	}

	// increment counter for the next transaction
	return txIdxBucket.Put(numTxKey, uint64KeyToBytes(nextTxKey+1))
}

func (c *TrackedTransactionStore) addTransactionInternal(
	txHashBytes []byte,
	tt *proto.TrackedTransaction,
	wd *proto.WatchedTxData,
) error {
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

		return saveTrackedTransaction(tx, transactionsBucketIdxBucket, transactionsBucket, txHashBytes, tt, wd)
	})
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

	msg := proto.TrackedTransaction{
		StakingTransaction: serializedTx,
		StakingScript:      txscript,
		StakingOutputIdx:   stakingOutputIndex,
		StakerAddress:      stakerAddress.EncodeAddress(),
		BtcSigType:         pop.BtcSigType,
		BabylonSigBtcPk:    pop.BabylonSigOverBtcPk,
		BtcSigBabylonSig:   pop.BtcSigOverBabylonSig,
		State:              proto.TransactionState_SENT_TO_BTC,
		Watched:            false,
		UnbondingTxData:    nil,
	}

	return c.addTransactionInternal(
		txHashBytes, &msg, nil,
	)
}

func (c *TrackedTransactionStore) AddWatchedTransaction(
	btcTx *wire.MsgTx,
	stakingOutputIndex uint32,
	txscript []byte,
	pop *ProofOfPossession,
	stakerAddress btcutil.Address,
	slashingTx *wire.MsgTx,
	slashingTxSig *schnorr.Signature,
	stakerBabylonPk *secp256k1.PubKey,
) error {
	txHash := btcTx.TxHash()
	txHashBytes := txHash[:]
	serializedTx, err := utils.SerializeBtcTransaction(btcTx)

	if err != nil {
		return err
	}

	msg := proto.TrackedTransaction{
		StakingTransaction: serializedTx,
		StakingScript:      txscript,
		StakingOutputIdx:   stakingOutputIndex,
		StakerAddress:      stakerAddress.EncodeAddress(),
		BtcSigType:         pop.BtcSigType,
		BabylonSigBtcPk:    pop.BabylonSigOverBtcPk,
		BtcSigBabylonSig:   pop.BtcSigOverBabylonSig,
		State:              proto.TransactionState_SENT_TO_BTC,
		Watched:            true,
		UnbondingTxData:    nil,
	}

	serializedSlashingtx, err := utils.SerializeBtcTransaction(slashingTx)
	if err != nil {
		return err
	}

	serializedSig := slashingTxSig.Serialize()

	watchedData := proto.WatchedTxData{
		SlashingTransaction:    serializedSlashingtx,
		SlashingTransactionSig: serializedSig,
		StakerBabylonPk:        stakerBabylonPk.Bytes(),
	}

	return c.addTransactionInternal(
		txHashBytes, &msg, &watchedData,
	)
}

func (c *TrackedTransactionStore) setTxState(
	txHash *chainhash.Hash,
	stateTransitionFn func(*proto.TrackedTransaction) error,
) error {
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

		if err := stateTransitionFn(&storedTx); err != nil {
			return err
		}

		marshalled, err := pm.Marshal(&storedTx)

		if err != nil {
			return err
		}

		err = transactionsBucket.Put(txKey, marshalled)

		if err != nil {
			return err
		}

		return nil
	})
}

func (c *TrackedTransactionStore) SetTxConfirmed(txHash *chainhash.Hash) error {
	setTxConfirmed := func(tx *proto.TrackedTransaction) error {
		tx.State = proto.TransactionState_CONFIRMED_ON_BTC
		return nil
	}

	return c.setTxState(txHash, setTxConfirmed)
}

func (c *TrackedTransactionStore) SetTxSentToBabylon(txHash *chainhash.Hash) error {
	setTxSentToBabylon := func(tx *proto.TrackedTransaction) error {
		tx.State = proto.TransactionState_SENT_TO_BABYLON
		return nil
	}

	return c.setTxState(txHash, setTxSentToBabylon)
}

func (c *TrackedTransactionStore) SetTxSpentOnBtc(txHash *chainhash.Hash) error {
	setTxSpentOnBtc := func(tx *proto.TrackedTransaction) error {
		tx.State = proto.TransactionState_SPENT_ON_BTC
		return nil
	}

	return c.setTxState(txHash, setTxSpentOnBtc)
}

func (c *TrackedTransactionStore) SetTxUnbondingStarted(
	txHash *chainhash.Hash,
	unbondingTx *wire.MsgTx,
	unbondingTxScript []byte,
) error {
	update, err := newInitialUnbondingTxData(unbondingTx, unbondingTxScript)

	if err != nil {
		return err
	}

	setUnbondingStarted := func(tx *proto.TrackedTransaction) error {
		if tx.UnbondingTxData != nil {
			return fmt.Errorf("cannot set unbonding started, because unbonding tx data already exists: %w", ErrInvalidUnbondingDataUpdate)
		}

		tx.State = proto.TransactionState_UNBONDING_STARTED
		tx.UnbondingTxData = update

		return nil
	}

	return c.setTxState(txHash, setUnbondingStarted)
}

func (c *TrackedTransactionStore) SetTxUnbondingSignaturesReceived(
	txHash *chainhash.Hash,
	validatorUnbondingSignature *schnorr.Signature,
	juryUnbondingSignature *schnorr.Signature,
) error {
	update, err := newUnbondingSignaturesUpdate(validatorUnbondingSignature, juryUnbondingSignature)

	if err != nil {
		return err
	}

	setUnbondingSignaturesReceived := func(tx *proto.TrackedTransaction) error {
		if tx.UnbondingTxData == nil {
			return fmt.Errorf("cannot set unbonding signatures received, because unbonding tx data does not exist: %w", ErrUnbondingDataNotFound)
		}

		if tx.UnbondingTxData.UnbondingTransactionJurySig != nil || tx.UnbondingTxData.UnbondingTransactionValidatorSig != nil {
			return fmt.Errorf("cannot set unbonding signatures received, because unbonding signatures already exist: %w", ErrInvalidUnbondingDataUpdate)
		}

		tx.State = proto.TransactionState_UNBONDING_SIGNATURES_RECEIVED
		tx.UnbondingTxData.UnbondingTransactionJurySig = update.UnbondingTransactionJurySig
		tx.UnbondingTxData.UnbondingTransactionValidatorSig = update.UnbondingTransactionValidatorSig
		return nil
	}

	return c.setTxState(txHash, setUnbondingSignaturesReceived)
}

func (c *TrackedTransactionStore) SetTxUnbondingConfirmedOnBtc(
	txHash *chainhash.Hash,
) error {
	setUnbondingConfirmedOnBtc := func(tx *proto.TrackedTransaction) error {
		tx.State = proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC
		return nil
	}

	return c.setTxState(txHash, setUnbondingConfirmedOnBtc)
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

func (c *TrackedTransactionStore) GetWatchedTransactionData(txHash *chainhash.Hash) (*WatchedTransactionData, error) {
	var watchedData *WatchedTransactionData
	txHashBytes := txHash.CloneBytes()

	err := c.db.View(func(tx kvdb.RTx) error {
		watchedTxDataBucket := tx.ReadBucket(watchedTxDataBucketName)

		if watchedTxDataBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		maybeWatchedData := watchedTxDataBucket.Get(txHashBytes)

		if maybeWatchedData == nil {
			return ErrWatchedDataNotFound
		}

		var watchedDataProto proto.WatchedTxData
		err := pm.Unmarshal(maybeWatchedData, &watchedDataProto)

		if err != nil {
			return ErrCorruptedTransactionsDb
		}

		watchedDataFromDb, err := protoWatchedDataToWatchedTransactionData(&watchedDataProto)

		if err != nil {
			return err
		}

		watchedData = watchedDataFromDb

		return nil
	}, func() {})

	if err != nil {
		return nil, err
	}

	return watchedData, nil
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

func (c *TrackedTransactionStore) ScanTrackedTransactions(scanFunc StoredTransactionScanFn, reset func()) error {
	return kvdb.View(c.db, func(tx kvdb.RTx) error {
		transactionsBucket := tx.ReadBucket(transactionBucketName)

		if transactionsBucket == nil {
			return ErrCorruptedTransactionsDb
		}

		return transactionsBucket.ForEach(func(k, v []byte) error {
			var storedTxProto proto.TrackedTransaction
			err := pm.Unmarshal(v, &storedTxProto)

			if err != nil {
				return ErrCorruptedTransactionsDb
			}

			txFromDb, err := protoTxToStoredTransaction(&storedTxProto)

			if err != nil {
				return err
			}

			return scanFunc(txFromDb)
		})
	}, reset)
}
