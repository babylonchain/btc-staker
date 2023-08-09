package stakerdb_test

import (
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/babylonchain/babylon/testutil/datagen"
	"github.com/babylonchain/btc-staker/proto"
	"github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

func MakeTestStore(t *testing.T) *stakerdb.TrackedTransactionStore {
	// First, create a temporary directory to be used for the duration of
	// this test.
	tempDirName := t.TempDir()

	cfg := stakercfg.DefaultDBConfig()

	cfg.DBPath = tempDirName

	backend, err := stakercfg.GetDbBackend(&cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		backend.Close()
	})

	store, err := stakerdb.NewTrackedTransactionStore(backend)
	require.NoError(t, err)

	return store
}

func genStoredTransaction(t *testing.T, r *rand.Rand) *stakerdb.StoredTransaction {
	btcTx := datagen.GenRandomTx(r)
	outputIdx := r.Uint32()
	script := datagen.GenRandomByteArray(r, 150)
	btcAddress, err := btcutil.NewAddressWitnessScriptHash(datagen.GenRandomByteArray(r, 32), &chaincfg.MainNetParams)
	require.NoError(t, err)

	return &stakerdb.StoredTransaction{
		BtcTx:              btcTx,
		StakingOutputIndex: outputIdx,
		TxScript:           script,
		Pop: &stakerdb.ProofOfPossession{
			BabylonSigOverBtcPk:         datagen.GenRandomByteArray(r, 64),
			BtcSchnorrSigOverBabylonSig: datagen.GenRandomByteArray(r, 64),
		},
		StakerAddress: btcAddress.String(),
	}
}

func genNStoredTransactions(t *testing.T, r *rand.Rand, n int) []*stakerdb.StoredTransaction {
	storedTxs := make([]*stakerdb.StoredTransaction, n)

	for i := 0; i < n; i++ {
		storedTxs[i] = genStoredTransaction(t, r)
	}

	return storedTxs
}

func TestEmptyStore(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	s := MakeTestStore(t)
	hash := datagen.GenRandomBtcdHash(r)
	tx, err := s.GetTransaction(&hash)
	require.Nil(t, tx)
	require.Error(t, err)
	require.True(t, errors.Is(err, stakerdb.ErrTransactionNotFound))
}

func FuzzStoringTxs(f *testing.F) {
	// only 3 seeds as this is pretty slow test opening/closing db
	datagen.AddRandomSeedsToFuzzer(f, 3)

	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))
		s := MakeTestStore(t)
		numTx := r.Intn(30) + 1
		generatedStoredTxs := genNStoredTransactions(t, r, numTx)
		for _, storedTx := range generatedStoredTxs {
			address, err := btcutil.DecodeAddress(storedTx.StakerAddress, &chaincfg.MainNetParams)
			require.NoError(t, err)
			err = s.AddTransaction(
				storedTx.BtcTx,
				storedTx.StakingOutputIndex,
				storedTx.TxScript,
				storedTx.Pop,
				address,
			)
			require.NoError(t, err)
		}

		for _, storedTx := range generatedStoredTxs {
			hash := storedTx.BtcTx.TxHash()
			tx, err := s.GetTransaction(&hash)
			require.NoError(t, err)
			require.Equal(t, storedTx.BtcTx, tx.BtcTx)
			require.Equal(t, storedTx.StakingOutputIndex, tx.StakingOutputIndex)
			require.Equal(t, storedTx.TxScript, tx.TxScript)
			require.Equal(t, storedTx.Pop, tx.Pop)
			require.Equal(t, storedTx.StakerAddress, tx.StakerAddress)
		}
	})
}

func TestStateTransitions(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	s := MakeTestStore(t)
	tx := genStoredTransaction(t, r)
	address, err := btcutil.DecodeAddress(tx.StakerAddress, &chaincfg.MainNetParams)
	require.NoError(t, err)

	txHash := tx.BtcTx.TxHash()

	err = s.AddTransaction(
		tx.BtcTx,
		tx.StakingOutputIndex,
		tx.TxScript,
		tx.Pop,
		address,
	)
	require.NoError(t, err)

	// Inital state
	storedTx, err := s.GetTransaction(&txHash)
	require.NoError(t, err)
	require.Equal(t, proto.TransactionState_SENT_TO_BTC, storedTx.State)
	// Confirmed
	err = s.SetTxConfirmed(&txHash)
	require.NoError(t, err)
	storedTx, err = s.GetTransaction(&txHash)
	require.NoError(t, err)
	require.Equal(t, proto.TransactionState_CONFIRMED_ON_BTC, storedTx.State)

	// Sent to Babylon
	err = s.SetTxSentToBabylon(&txHash)
	require.NoError(t, err)
	storedTx, err = s.GetTransaction(&txHash)
	require.NoError(t, err)
	require.Equal(t, proto.TransactionState_SENT_TO_BABYLON, storedTx.State)

	// Spent on BTC
	err = s.SetTxSpentOnBtc(&txHash)
	require.NoError(t, err)
	storedTx, err = s.GetTransaction(&txHash)
	require.NoError(t, err)
	require.Equal(t, proto.TransactionState_SPENT_ON_BTC, storedTx.State)
}