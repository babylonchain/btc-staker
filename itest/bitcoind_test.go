//go:build bitcoind
// +build bitcoind

package e2etest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/babylonchain/babylon/btcstaking"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

var (
	netParams = &chaincfg.RegressionNetParams
)

type BitcoindTestController struct {
	h      *BitcoindTestHandler
	client *rpcclient.Client
	pass   string
}

func startBitcoindTestController(t *testing.T) *BitcoindTestController {
	// Start bitcoind
	h := NewBitcoindHandler(t)
	h.Start()
	passphrase := "pass"
	_ = h.CreateWallet("test-wallet", passphrase)
	// only outputs which are 100 deep are mature, so this wallet will have 100 mature outputs
	_ = h.GenerateBlocks(int(100) + 100)
	bitcoindHost := "127.0.0.1:18443"
	bitcoindUser := "user"
	bitcoindPass := "pass"
	testRpcClient, err := rpcclient.New(&rpcclient.ConnConfig{
		Host:                 bitcoindHost,
		User:                 bitcoindUser,
		Pass:                 bitcoindPass,
		DisableTLS:           true,
		DisableConnectOnNew:  true,
		DisableAutoReconnect: false,
		// we use post mode as it sure it works with either bitcoind or btcwallet
		// we may need to re-consider it later if we need any notifications
		HTTPPostMode: true,
	}, nil)
	require.NoError(t, err)

	return &BitcoindTestController{
		h:      h,
		client: testRpcClient,
		pass:   passphrase,
	}
}

func pubKeyFromString(t *testing.T, str string) *btcec.PublicKey {
	decoded, err := hex.DecodeString(str)
	require.NoError(t, err)
	pubKeyBytes, err := btcec.ParsePubKey(decoded)
	require.NoError(t, err)
	return pubKeyBytes
}

func getStakingOuputIdx(tx *wire.MsgTx, output *wire.TxOut) (int, error) {
	for i, out := range tx.TxOut {
		if out.Value == output.Value && bytes.Equal(out.PkScript, output.PkScript) {
			return i, nil
		}
	}
	return -1, fmt.Errorf("output not found")
}

func TestBitcoindOperations(t *testing.T) {
	c := startBitcoindTestController(t)
	magicBytes := []byte{0x01, 0x02, 0x03, 0x04}
	stakingTime := uint16(1000)
	stakingAmount := btcutil.Amount(1000000)
	quorum := uint32(1)
	covenantKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	fpPk, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	addr, err := c.client.GetNewAddress("")
	require.NoError(t, err)

	info, err := c.client.GetAddressInfo(addr.EncodeAddress())
	require.NoError(t, err)

	stakerKey := pubKeyFromString(t, *info.PubKey)

	// 1. Initial staking flow:
	// - create unfunded staking transaction
	// - fund it using bitcoind fundrawtransaction endpoint
	// - sign it using bitcoind signrawtransactionwithwallet endpoint
	// - send it using bitcoind sendrawtransaction endpoint
	stakingInfo, unfundedStakingTx, err := btcstaking.BuildV0IdentifiableStakingOutputsAndTx(
		magicBytes,
		stakerKey,
		fpPk.PubKey(),
		[]*btcec.PublicKey{covenantKey.PubKey()},
		quorum,
		stakingTime,
		stakingAmount,
		netParams,
	)
	require.NoError(t, err)
	feerate := float64(0.0001)
	fundedResult, err := c.client.FundRawTransaction(unfundedStakingTx, btcjson.FundRawTransactionOpts{
		FeeRate: &feerate,
	}, nil)
	require.NoError(t, err)
	require.Len(t, fundedResult.Transaction.TxOut, 3)

	stakingOutputIdx, err := getStakingOuputIdx(fundedResult.Transaction, stakingInfo.StakingOutput)
	require.NoError(t, err)

	err = c.client.WalletPassphrase(c.pass, 20)
	require.NoError(t, err)

	signedResult, allSigned, err := c.client.SignRawTransactionWithWallet(fundedResult.Transaction)
	require.NoError(t, err)
	require.True(t, allSigned)

	stakingTxHash, err := c.client.SendRawTransaction(signedResult, true)
	_ = c.h.GenerateBlocks(3)
	result, err := c.client.GetTransaction(stakingTxHash)
	require.NoError(t, err)
	require.NotNil(t, result)

	// 2. Check signing unbonding transaction by using PSBT and Bitcoind processPsbt endpoint:
	// This is how staker or covenant should sign unbonding/slashing transactions
	unbondingTime := uint16(100)
	ubdInfo, err := btcstaking.BuildUnbondingInfo(
		stakerKey,
		[]*btcec.PublicKey{fpPk.PubKey()},
		[]*btcec.PublicKey{covenantKey.PubKey()},
		quorum,
		unbondingTime,
		stakingAmount-10000,
		netParams,
	)
	require.NoError(t, err)
	stakingOutput := stakingInfo.StakingOutput

	manualUnbondingTx := wire.NewMsgTx(2)
	manualUnbondingTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(stakingTxHash, uint32(stakingOutputIdx)), nil, nil))
	manualUnbondingTx.AddTxOut(ubdInfo.UnbondingOutput)

	// First prepare PSBT Packet for signing
	psbtPacket, err := psbt.New(
		[]*wire.OutPoint{wire.NewOutPoint(stakingTxHash, uint32(stakingOutputIdx))},
		[]*wire.TxOut{ubdInfo.UnbondingOutput},
		2,
		0,
		[]uint32{wire.MaxTxInSequenceNum},
	)
	require.NoError(t, err)

	unbondingPathSpendInfo, err := stakingInfo.UnbondingPathSpendInfo()
	require.NoError(t, err)
	unbondingCtlBlockBytes, err := unbondingPathSpendInfo.ControlBlock.ToBytes()
	require.NoError(t, err)
	unbondingLeaf := unbondingPathSpendInfo.RevealedLeaf
	unbondingLeafHash := unbondingLeaf.TapHash()

	// This seems to be minimal set of data reuire to sign taproot script spend using
	// psbt bitcoind api
	psbtPacket.Inputs[0].SighashType = txscript.SigHashDefault
	psbtPacket.Inputs[0].WitnessUtxo = stakingOutput
	psbtPacket.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{
		&psbt.Bip32Derivation{
			PubKey: stakerKey.SerializeCompressed(),
		},
	}
	psbtPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		&psbt.TaprootTapLeafScript{
			ControlBlock: unbondingCtlBlockBytes,
			Script:       unbondingLeaf.Script,
			LeafVersion:  unbondingLeaf.LeafVersion,
		},
	}

	encodedPacket, err := psbtPacket.B64Encode()
	require.NoError(t, err)
	signAll := true
	psbtProcessResult, err := c.client.WalletProcessPsbt(
		encodedPacket,
		&signAll,
		"DEFAULT",
		nil,
	)
	require.NoError(t, err)
	dec, err := base64.StdEncoding.DecodeString(psbtProcessResult.Psbt)
	require.NoError(t, err)
	packetDecoded, err := psbt.NewFromRawBytes(bytes.NewReader(dec), false)
	require.NoError(t, err)

	// Verify processed PSBT packet has all values are expected
	require.Len(t, packetDecoded.Inputs, 1)
	require.True(t, packetDecoded.Inputs[0].IsSane())
	require.Len(t, packetDecoded.Inputs[0].TaprootScriptSpendSig, 1)
	require.Equal(t, schnorr.SerializePubKey(stakerKey), packetDecoded.Inputs[0].TaprootScriptSpendSig[0].XOnlyPubKey)
	require.Equal(t, unbondingLeafHash.CloneBytes(), packetDecoded.Inputs[0].TaprootScriptSpendSig[0].LeafHash)
	require.Equal(t, txscript.SigHashDefault, packetDecoded.Inputs[0].TaprootScriptSpendSig[0].SigHash)
	require.Equal(t, *stakingOutput, *packetDecoded.Inputs[0].WitnessUtxo)
	require.Equal(t, manualUnbondingTx.TxHash(), packetDecoded.UnsignedTx.TxHash())
	require.Equal(t, manualUnbondingTx.WitnessHash(), packetDecoded.UnsignedTx.WitnessHash())

	sigFromPsbt, err := schnorr.ParseSignature(packetDecoded.Inputs[0].TaprootScriptSpendSig[0].Signature)
	require.NoError(t, err)

	//
	sigVerificationError := btcstaking.VerifyTransactionSigWithOutput(
		packetDecoded.UnsignedTx,
		stakingOutput,
		unbondingLeaf.Script,
		stakerKey,
		sigFromPsbt.Serialize(),
	)
	require.NoError(t, sigVerificationError)
}
