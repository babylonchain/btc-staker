package staker_test

import (
	"encoding/hex"
	"math"
	"math/rand"
	"testing"

	dg "github.com/babylonchain/babylon/testutil/datagen"
	st "github.com/babylonchain/btc-staker/staker"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

func FuzzScriptGeneration(f *testing.F) {
	dg.AddRandomSeedsToFuzzer(f, 10)

	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))

		stakerPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		delegatorPrivkey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		jurPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		stakerPk := hex.EncodeToString(schnorr.SerializePubKey(stakerPrivKey.PubKey()))
		delegatorPk := hex.EncodeToString(schnorr.SerializePubKey(delegatorPrivkey.PubKey()))
		juryPk := hex.EncodeToString(schnorr.SerializePubKey(jurPrivKey.PubKey()))
		stakingTime := uint64(r.Int31n(math.MaxUint16))

		resp, err := st.GenerateStakingScriptAndAddress(stakerPk, delegatorPk, juryPk, stakingTime, &chaincfg.MainNetParams)
		require.NoError(t, err)

		// check that the script is valid hex
		_, err = hex.DecodeString(resp.Script)
		require.NoError(t, err)

		// check that the address is bech32
		_, err = btcutil.DecodeAddress(resp.Address, &chaincfg.MainNetParams)
		require.NoError(t, err)
	})
}
