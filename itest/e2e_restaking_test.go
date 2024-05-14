//go:build e2e
// +build e2e

package e2etest

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/babylonchain/babylon/testutil/datagen"
	bbntypes "github.com/babylonchain/babylon/types"
	btcstypes "github.com/babylonchain/babylon/x/btcstaking/types"
	bsctypes "github.com/babylonchain/babylon/x/btcstkconsumer/types"
	"github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/proto"
	"github.com/babylonchain/btc-staker/staker"
	"github.com/babylonchain/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sttypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/stretchr/testify/require"
)

type testStakingDataWithCZFPs struct {
	*testStakingData
	consumerRegister *bsctypes.ConsumerRegister
	CZFPBabylonSKs   []*secp256k1.PrivKey
	CZFPBabylonPKs   []*secp256k1.PubKey
	CZFPBTCSKs       []*btcec.PrivateKey
	CZFPBTCPKs       []*btcec.PublicKey
}

func (d *testStakingDataWithCZFPs) GetNumRestakedFPsInCZ() int {
	return len(d.CZFPBabylonSKs)
}

func (tm *TestManager) getTestStakingDataWithCZFPs(
	t *testing.T,
	stakerKey *btcec.PublicKey,
	stakingTime uint16,
	stakingAmount int64,
	numRestakedFPs int,
	numRestakedConsumerChainFPs int,
) *testStakingDataWithCZFPs {
	data := &testStakingDataWithCZFPs{}
	data.testStakingData = tm.getTestStakingData(t, stakerKey, stakingTime, stakingAmount, numRestakedFPs)

	fpBTCSKs, fpBTCPKs, err := datagen.GenRandomBTCKeyPairs(r, numRestakedConsumerChainFPs)
	require.NoError(t, err)

	fpBBNSKs, fpBBNPKs := []*secp256k1.PrivKey{}, []*secp256k1.PubKey{}
	for i := 0; i < numRestakedConsumerChainFPs; i++ {
		fpBBNSK := secp256k1.GenPrivKey()
		fpBBNSKs = append(fpBBNSKs, fpBBNSK)
		fpBBNPK := fpBBNSK.PubKey().(*secp256k1.PubKey)
		fpBBNPKs = append(fpBBNPKs, fpBBNPK)
	}

	data.CZFPBabylonSKs = fpBBNSKs
	data.CZFPBabylonPKs = fpBBNPKs
	data.CZFPBTCSKs = fpBTCSKs
	data.CZFPBTCPKs = fpBTCPKs
	data.consumerRegister = datagen.GenRandomConsumerRegister(r)

	return data
}

func (tm *TestManager) createAndRegisterFinalityProvidersWithCZ(
	t *testing.T,
	data *testStakingDataWithCZFPs,
) {
	// register chain
	_, err := tm.BabylonClient.RegisterConsumerChain(data.consumerRegister.ConsumerId, data.consumerRegister.ConsumerName, data.consumerRegister.ConsumerDescription)
	require.NoError(t, err)

	// create and register finality providers for consumer chains
	for i := 0; i < data.GetNumRestakedFPsInCZ(); i++ {
		// ensure the finality provider in data does not exist yet
		fpResp, err := tm.BabylonClient.QueryFinalityProvider(data.CZFPBTCPKs[i])
		require.Nil(t, fpResp)
		require.Error(t, err)
		require.True(t, errors.Is(err, babylonclient.ErrFinalityProviderDoesNotExist))

		pop, err := btcstypes.NewPoP(data.CZFPBabylonSKs[i], data.CZFPBTCSKs[i])
		require.NoError(t, err)

		fpPK := data.CZFPBTCPKs[i]
		fpBTCPK := bbntypes.NewBIP340PubKeyFromBTCPK(fpPK)

		params, err := tm.BabylonClient.QueryStakingTracker()
		require.NoError(t, err)

		_, p, err := eots.NewMasterRandPair(r)
		require.NoError(t, err)

		// register the generated finality provider
		_, err = tm.BabylonClient.RegisterFinalityProvider(
			data.CZFPBabylonPKs[i],
			fpBTCPK,
			&params.MinComissionRate,
			&sttypes.Description{
				Moniker: "tester",
			},
			pop,
			data.consumerRegister.ConsumerId,
		)

		// ensure the finality provider has been registered
		fp, err := tm.BabylonClient.QueryFinalityProvider(fpPK)
		require.NoError(t, err)
		require.Equal(t, bbntypes.NewBIP340PubKeyFromBTCPK(&fp.FinalityProvider.BtcPk), fpBTCPK)
	}

	// create and register finality providers for Babylon
	tm.createAndRegisterFinalityProviders(t, data.testStakingData)
}

func (tm *TestManager) sendStakingTxWithCZFPs(t *testing.T, data *testStakingDataWithCZFPs) *chainhash.Hash {
	fpBTCPKs := []string{}
	// Babylon FP PKs
	for i := 0; i < data.GetNumRestakedFPs(); i++ {
		fpBTCPK := hex.EncodeToString(schnorr.SerializePubKey(data.testStakingData.FinalityProviderBtcKeys[i]))
		fpBTCPKs = append(fpBTCPKs, fpBTCPK)
	}
	// consumer chain FP PKs
	for i := 0; i < data.GetNumRestakedFPsInCZ(); i++ {
		fpBTCPK := hex.EncodeToString(schnorr.SerializePubKey(data.CZFPBTCPKs[i]))
		fpBTCPKs = append(fpBTCPKs, fpBTCPK)
	}
	// restake
	res, err := tm.StakerClient.Stake(
		context.Background(),
		tm.MinerAddr.String(),
		data.StakingAmount,
		fpBTCPKs,
		int64(data.StakingTime),
	)
	require.NoError(t, err)
	txHash := res.TxHash

	stakingDetails, err := tm.StakerClient.StakingDetails(context.Background(), txHash)
	require.NoError(t, err)
	require.Equal(t, stakingDetails.StakingTxHash, txHash)
	require.Equal(t, stakingDetails.StakingState, proto.TransactionState_SENT_TO_BTC.String())

	hashFromString, err := chainhash.NewHashFromStr(txHash)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.TestRpcClient, []*chainhash.Hash{hashFromString})
		return len(txFromMempool) == 1
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	mBlock := tm.mineBlock(t)
	require.Equal(t, 2, len(mBlock.Transactions))

	_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&mBlock.Header})
	require.NoError(t, err)

	return hashFromString
}

func TestRestakingToConsumerChains(t *testing.T) {
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	stakingTime := uint16(staker.GetMinStakingTime(params))

	// restaked to 2 Babylon finality providers and 3 CZ finality providers
	data := tm.getTestStakingDataWithCZFPs(t, tm.WalletPrivKey.PubKey(), stakingTime, 10000, 2, 3)

	hashed, err := chainhash.NewHash(datagen.GenRandomByteArray(r, 32))
	require.NoError(t, err)
	scr, err := txscript.PayToTaprootScript(tm.CovenantPrivKeys[0].PubKey())
	require.NoError(t, err)
	_, st, erro := tm.Sa.Wallet().TxDetails(hashed, scr)
	// query for existing tx is not an error, proper state should be returned
	require.NoError(t, erro)
	require.Equal(t, st, walletcontroller.TxNotFound)

	tm.createAndRegisterFinalityProvidersWithCZ(t, data)

	txHash := tm.sendStakingTxWithCZFPs(t, data)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)
	// need to activate delegation to unbond
	tm.insertCovenantSigForDelegation(t, pend[0])
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_DELEGATION_ACTIVE)
}
