package stakerdb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/babylonchain/btc-staker/proto"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/btcec/v2"
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

type PubKeySigPair struct {
	Signature *schnorr.Signature
	PubKey    *btcec.PublicKey
}

func NewCovenantMemberSignature(
	sig *schnorr.Signature,
	pubKey *btcec.PublicKey,
) PubKeySigPair {
	return PubKeySigPair{
		sig,
		pubKey,
	}
}

func covenantSigToProto(c *PubKeySigPair) *proto.CovenantSig {
	return &proto.CovenantSig{
		CovenantSig:      c.Signature.Serialize(),
		CovenantSigBtcPk: schnorr.SerializePubKey(c.PubKey),
	}
}

func covenantSigsToProto(c []PubKeySigPair) []*proto.CovenantSig {
	protoC := make([]*proto.CovenantSig, len(c))

	for i, sig := range c {
		protoC[i] = covenantSigToProto(&sig)
	}

	return protoC
}

func covenantSigFromProto(c *proto.CovenantSig) (*PubKeySigPair, error) {
	sig, err := schnorr.ParseSignature(c.CovenantSig)

	if err != nil {
		return nil, err
	}

	pubKey, err := schnorr.ParsePubKey(c.CovenantSigBtcPk)

	if err != nil {
		return nil, err
	}

	return &PubKeySigPair{
		Signature: sig,
		PubKey:    pubKey,
	}, nil
}

type BtcConfirmationInfo struct {
	Height    uint32
	BlockHash chainhash.Hash
}

type StoredTransaction struct {
	StoredTransactionIdx      uint64
	StakingTx                 *wire.MsgTx
	StakingOutputIndex        uint32
	StakingTxConfirmationInfo *BtcConfirmationInfo
	StakingTime               uint16
	ValidatorBtcPks           []*btcec.PublicKey
	Pop                       *ProofOfPossession
	// Returning address as string, to avoid having to know how to decode address
	// which requires knowing the network we are on
	StakerAddress           string
	SlashingTxChangeAddress string
	State                   proto.TransactionState
	Watched                 bool
	UnbondingTxData         *UnbondingStoreData
}

type WatchedTransactionData struct {
	SlashingTx          *wire.MsgTx
	SlashingTxSig       *schnorr.Signature
	StakerBabylonPubKey *secp256k1.PubKey
	StakerBtcPubKey     *btcec.PublicKey
}

type UnbondingStoreData struct {
	UnbondingTx                 *wire.MsgTx
	UnbondingTime               uint16
	CovenantSignatures          []PubKeySigPair
	UnbondingTxConfirmationInfo *BtcConfirmationInfo
}

func newInitialUnbondingTxData(
	unbondingTx *wire.MsgTx,
	unbondingTime uint16,
) (*proto.UnbondingTxData, error) {
	if unbondingTx == nil {
		return nil, fmt.Errorf("cannot create unbonding tx data without unbonding tx")
	}

	serializedTx, err := utils.SerializeBtcTransaction(unbondingTx)

	if err != nil {
		return nil, fmt.Errorf("cannot create unbonding tx data: %w", err)
	}

	unbondingData := &proto.UnbondingTxData{
		UnbondingTransaction:           serializedTx,
		UnbondingTime:                  uint32(unbondingTime),
		CovenantSignatures:             make([]*proto.CovenantSig, 0),
		UnbondingTxBtcConfirmationInfo: nil,
	}

	return unbondingData, nil
}

type WithdrawableTransactionsFilter struct {
	currentBestBlockHeight uint32
}
type StoredTransactionQuery struct {
	IndexOffset uint64

	NumMaxTransactions uint64

	Reversed bool

	withdrawableTransactionsFilter *WithdrawableTransactionsFilter
}

func DefaultStoredTransactionQuery() StoredTransactionQuery {
	return StoredTransactionQuery{
		IndexOffset:                    0,
		NumMaxTransactions:             50,
		Reversed:                       false,
		withdrawableTransactionsFilter: nil,
	}
}

func (q *StoredTransactionQuery) WithdrawableTransactionsFilter(currentBestBlock uint32) StoredTransactionQuery {
	q.withdrawableTransactionsFilter = &WithdrawableTransactionsFilter{
		currentBestBlockHeight: currentBestBlock,
	}

	return *q
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

func protoBtcConfirmationInfoToBtcConfirmationInfo(ci *proto.BTCConfirmationInfo) (*BtcConfirmationInfo, error) {
	if ci == nil {
		return nil, nil
	}

	hash, err := chainhash.NewHash(ci.BlockHash)

	if err != nil {
		return nil, err
	}

	return &BtcConfirmationInfo{
		Height:    ci.BlockHeight,
		BlockHash: *hash,
	}, nil

}

func protoUnbondingDataToUnbondingStoreData(ud *proto.UnbondingTxData) (*UnbondingStoreData, error) {
	// Unbodning txdata should always contains unbonding tx
	var unbondingTx wire.MsgTx
	err := unbondingTx.Deserialize(bytes.NewReader(ud.UnbondingTransaction))

	if err != nil {
		return nil, err
	}

	if ud.UnbondingTime > math.MaxUint16 {
		return nil, fmt.Errorf("unbonding time is too large. Max value is %d", math.MaxUint16)
	}

	var sigs []PubKeySigPair

	for _, sig := range ud.CovenantSignatures {
		covenantSig, err := covenantSigFromProto(sig)

		if err != nil {
			return nil, err
		}

		sigs = append(sigs, *covenantSig)
	}

	unbondingTxConfirmationInfo, err := protoBtcConfirmationInfoToBtcConfirmationInfo(ud.UnbondingTxBtcConfirmationInfo)

	if err != nil {
		return nil, err
	}

	return &UnbondingStoreData{
		UnbondingTx:                 &unbondingTx,
		UnbondingTime:               uint16(ud.UnbondingTime),
		CovenantSignatures:          sigs,
		UnbondingTxConfirmationInfo: unbondingTxConfirmationInfo,
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

	stakingTxConfgInfo, err := protoBtcConfirmationInfoToBtcConfirmationInfo(ttx.StakingTxBtcConfirmationInfo)

	if err != nil {
		return nil, err
	}

	if ttx.StakingTime > math.MaxUint16 {
		return nil, fmt.Errorf("staking time is too large. Max value is %d", math.MaxUint16)
	}

	var validatorPubkeys []*btcec.PublicKey = make([]*btcec.PublicKey, len(ttx.ValidatorBtcPks))

	for i, pk := range ttx.ValidatorBtcPks {
		validatorPubkeys[i], err = schnorr.ParsePubKey(pk)

		if err != nil {
			return nil, err
		}
	}

	return &StoredTransaction{
		StoredTransactionIdx:      ttx.TrackedTransactionIdx,
		StakingTx:                 &stakingTx,
		StakingOutputIndex:        ttx.StakingOutputIdx,
		StakingTxConfirmationInfo: stakingTxConfgInfo,
		StakingTime:               uint16(ttx.StakingTime),
		ValidatorBtcPks:           validatorPubkeys,
		Pop: &ProofOfPossession{
			BtcSigType:           ttx.BtcSigType,
			BabylonSigOverBtcPk:  ttx.BabylonSigBtcPk,
			BtcSigOverBabylonSig: ttx.BtcSigBabylonSig,
		},
		StakerAddress:           ttx.StakerAddress,
		SlashingTxChangeAddress: ttx.SlashingTxChangeAddress,
		State:                   ttx.State,
		Watched:                 ttx.Watched,
		UnbondingTxData:         utd,
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

	stakerBtcKey, err := schnorr.ParsePubKey(wd.StakerBtcPk)

	if err != nil {
		return nil, err
	}

	return &WatchedTransactionData{
		SlashingTx:          &slashingTx,
		SlashingTxSig:       schnorSig,
		StakerBabylonPubKey: &stakerBabylonKey,
		StakerBtcPubKey:     stakerBtcKey,
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
	nextTxKey := nextTxKey(txIdxBucket)

	tx.TrackedTransactionIdx = nextTxKey

	marshalled, err := pm.Marshal(tx)

	if err != nil {
		return err
	}

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
	stakingTime uint16,
	validatorPubKeys []*btcec.PublicKey,
	pop *ProofOfPossession,
	stakerAddress, slashingTxChangeAddress btcutil.Address,
) error {
	txHash := btcTx.TxHash()
	txHashBytes := txHash[:]
	serializedTx, err := utils.SerializeBtcTransaction(btcTx)

	if err != nil {
		return err
	}

	if len(validatorPubKeys) == 0 {
		return fmt.Errorf("cannot add transaction without validator public keys")
	}

	var validatorPubKeysBytes [][]byte = make([][]byte, len(validatorPubKeys))

	for i, pk := range validatorPubKeys {
		validatorPubKeysBytes[i] = schnorr.SerializePubKey(pk)
	}

	msg := proto.TrackedTransaction{
		// Setting it to 0, proper number will be filled by `addTransactionInternal`
		TrackedTransactionIdx:        0,
		StakingTransaction:           serializedTx,
		StakingOutputIdx:             stakingOutputIndex,
		StakerAddress:                stakerAddress.EncodeAddress(),
		StakingTime:                  uint32(stakingTime),
		ValidatorBtcPks:              validatorPubKeysBytes,
		SlashingTxChangeAddress:      slashingTxChangeAddress.EncodeAddress(),
		StakingTxBtcConfirmationInfo: nil,
		BtcSigType:                   pop.BtcSigType,
		BabylonSigBtcPk:              pop.BabylonSigOverBtcPk,
		BtcSigBabylonSig:             pop.BtcSigOverBabylonSig,
		State:                        proto.TransactionState_SENT_TO_BTC,
		Watched:                      false,
		UnbondingTxData:              nil,
	}

	return c.addTransactionInternal(
		txHashBytes, &msg, nil,
	)
}

func (c *TrackedTransactionStore) AddWatchedTransaction(
	btcTx *wire.MsgTx,
	stakingOutputIndex uint32,
	stakingTime uint16,
	validatorPubKeys []*btcec.PublicKey,
	pop *ProofOfPossession,
	stakerAddress, slashingTxChangeAddress btcutil.Address,
	slashingTx *wire.MsgTx,
	slashingTxSig *schnorr.Signature,
	stakerBabylonPk *secp256k1.PubKey,
	stakerBtcPk *btcec.PublicKey,
) error {
	txHash := btcTx.TxHash()
	txHashBytes := txHash[:]
	serializedTx, err := utils.SerializeBtcTransaction(btcTx)

	if err != nil {
		return err
	}

	if len(validatorPubKeys) == 0 {
		return fmt.Errorf("cannot add transaction without validator public keys")
	}

	var validatorPubKeysBytes [][]byte = make([][]byte, len(validatorPubKeys))

	for i, pk := range validatorPubKeys {
		validatorPubKeysBytes[i] = schnorr.SerializePubKey(pk)
	}

	msg := proto.TrackedTransaction{
		// Setting it to 0, proper number will be filled by `addTransactionInternal`
		TrackedTransactionIdx:        0,
		StakingTransaction:           serializedTx,
		StakingOutputIdx:             stakingOutputIndex,
		StakerAddress:                stakerAddress.EncodeAddress(),
		StakingTime:                  uint32(stakingTime),
		ValidatorBtcPks:              validatorPubKeysBytes,
		SlashingTxChangeAddress:      slashingTxChangeAddress.EncodeAddress(),
		StakingTxBtcConfirmationInfo: nil,
		BtcSigType:                   pop.BtcSigType,
		BabylonSigBtcPk:              pop.BabylonSigOverBtcPk,
		BtcSigBabylonSig:             pop.BtcSigOverBabylonSig,
		State:                        proto.TransactionState_SENT_TO_BTC,
		Watched:                      true,
		UnbondingTxData:              nil,
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
		StakerBtcPk:            schnorr.SerializePubKey(stakerBtcPk),
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

func (c *TrackedTransactionStore) SetTxConfirmed(
	txHash *chainhash.Hash,
	blockHash *chainhash.Hash,
	blockHeight uint32,
) error {
	setTxConfirmed := func(tx *proto.TrackedTransaction) error {
		tx.State = proto.TransactionState_CONFIRMED_ON_BTC
		tx.StakingTxBtcConfirmationInfo = &proto.BTCConfirmationInfo{
			BlockHash:   blockHash.CloneBytes(),
			BlockHeight: blockHeight,
		}
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
	unbondingTime uint16,
) error {
	update, err := newInitialUnbondingTxData(unbondingTx, unbondingTime)

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
	covenantSignatures []PubKeySigPair,
) error {
	setUnbondingSignaturesReceived := func(tx *proto.TrackedTransaction) error {
		if tx.UnbondingTxData == nil {
			return fmt.Errorf("cannot set unbonding signatures received, because unbonding tx data does not exist: %w", ErrUnbondingDataNotFound)
		}

		if len(tx.UnbondingTxData.CovenantSignatures) > 0 {
			return fmt.Errorf("cannot set unbonding signatures received, because unbonding signatures already exist: %w", ErrInvalidUnbondingDataUpdate)
		}

		tx.State = proto.TransactionState_UNBONDING_SIGNATURES_RECEIVED
		tx.UnbondingTxData.CovenantSignatures = covenantSigsToProto(covenantSignatures)
		return nil
	}

	return c.setTxState(txHash, setUnbondingSignaturesReceived)
}

func (c *TrackedTransactionStore) SetTxUnbondingConfirmedOnBtc(
	txHash *chainhash.Hash,
	blockHash *chainhash.Hash,
	blockHeight uint32,
) error {
	setUnbondingConfirmedOnBtc := func(tx *proto.TrackedTransaction) error {
		if tx.UnbondingTxData == nil {
			return fmt.Errorf("cannot set unbonding confirmed on btc, because unbonding tx data does not exist: %w", ErrUnbondingDataNotFound)
		}

		tx.State = proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC
		tx.UnbondingTxData.UnbondingTxBtcConfirmationInfo = &proto.BTCConfirmationInfo{
			BlockHash:   blockHash.CloneBytes(),
			BlockHeight: blockHeight,
		}
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

func isTimeLockExpired(confirmationBlockHeight uint32, lockTime uint16, currentBestBlockHeight uint32) bool {
	// transaction maybe included/executed only in next possible block
	nexBlockHeight := int64(currentBestBlockHeight) + 1
	pastLock := nexBlockHeight - int64(confirmationBlockHeight) - int64(lockTime)
	return pastLock >= 0
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

			// we have query only for withdrawable transaction i.e transactions which
			// either in SENT_TO_BABYLON or UNBONDING_CONFIRMED_ON_BTC state and which timelock has expired
			if q.withdrawableTransactionsFilter != nil {
				var confirmationHeight uint32
				var scriptTimeLock uint16

				if txFromDb.Watched {
					// cannot withdraw watched transaction directly through staker program
					// at least for now.
					return false, nil
				}

				if txFromDb.State == proto.TransactionState_SENT_TO_BABYLON {
					scriptTimeLock = txFromDb.StakingTime
					confirmationHeight = txFromDb.StakingTxConfirmationInfo.Height
				} else if txFromDb.State == proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC {
					scriptTimeLock = txFromDb.UnbondingTxData.UnbondingTime
					confirmationHeight = txFromDb.UnbondingTxData.UnbondingTxConfirmationInfo.Height
				} else {
					return false, nil
				}

				timeLockExpired := isTimeLockExpired(
					confirmationHeight,
					scriptTimeLock,
					q.withdrawableTransactionsFilter.currentBestBlockHeight,
				)

				if timeLockExpired {
					resp.Transactions = append(resp.Transactions, *txFromDb)
					return true, nil
				} else {
					return false, nil
				}
			} else {
				resp.Transactions = append(resp.Transactions, *txFromDb)
				return true, nil
			}
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
