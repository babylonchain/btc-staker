package staker_test

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"testing"

	dg "github.com/babylonchain/babylon/testutil/datagen"
	st "github.com/babylonchain/btc-staker/staker"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
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

func TestFooo(t *testing.T) {

	var DefaultRelayFeePerKb btcutil.Amount = 1e3
	var FeePerKwFloor chainfee.SatPerKWeight = 250

	satKW := chainfee.SatPerKWeight(12500)

	satKb := satKW.FeePerKVByte()

	fallRate := chainfee.SatPerKVByte(25 * 1000)

	fmt.Println(satKb)
	fmt.Println(satKb / 1000)
	fmt.Println(DefaultRelayFeePerKb)
	fmt.Println(FeePerKwFloor.FeePerKVByte())
	fmt.Println("fall rate")
	fmt.Println(fallRate)

	require.Equal(t, 1, 1)
}
