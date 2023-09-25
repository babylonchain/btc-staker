package staker

import (
	"fmt"

	staking "github.com/babylonchain/babylon/btcstaking"

	cl "github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/proto"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

type spendStakeTxInfo struct {
	spendStakeTx        *wire.MsgTx
	fundingOutput       *wire.TxOut
	fundingOutputScript []byte
	calculatedFee       btcutil.Amount
}

// babylonPopToDbPop receives already validated pop from external sources and converts it to database representation
func babylonPopToDbPop(pop *cl.BabylonPop) *stakerdb.ProofOfPossession {
	return &stakerdb.ProofOfPossession{
		BtcSigType:           uint32(pop.BtcSigType),
		BabylonSigOverBtcPk:  pop.BabylonEcdsaSigOverBtcPk,
		BtcSigOverBabylonSig: pop.BtcSig,
	}
}

func createDelegationData(
	inclusionBlock *wire.MsgBlock,
	stakingTxIdx uint32,
	storedTx *stakerdb.StoredTransaction,
	slashingTx *wire.MsgTx,
	slashingTxSignature *schnorr.Signature,
	babylonPubKey *secp256k1.PubKey,
	stakingTxInclusionProof []byte,
) *cl.DelegationData {
	inclusionBlockHash := inclusionBlock.BlockHash()

	dg := cl.DelegationData{
		StakingTransaction:                   storedTx.StakingTx,
		StakingTransactionIdx:                stakingTxIdx,
		StakingTransactionScript:             storedTx.TxScript,
		StakingTransactionInclusionProof:     stakingTxInclusionProof,
		StakingTransactionInclusionBlockHash: &inclusionBlockHash,
		SlashingTransaction:                  slashingTx,
		SlashingTransactionSig:               slashingTxSignature,
		BabylonPk:                            babylonPubKey,
		BabylonPop:                           storedTx.Pop,
	}

	return &dg
}

func createSpendStakeTx(
	destinationScript []byte,
	fundingOutput *wire.TxOut,
	fundingOutputIdx uint32,
	fundingTxHash *chainhash.Hash,
	lockTime uint16,
	feeRate chainfee.SatPerKVByte,
) (*wire.MsgTx, *btcutil.Amount, error) {
	newOutput := wire.NewTxOut(fundingOutput.Value, destinationScript)

	stakingOutputOutpoint := wire.NewOutPoint(fundingTxHash, fundingOutputIdx)
	stakingOutputAsInput := wire.NewTxIn(stakingOutputOutpoint, nil, nil)
	// need to set valid sequence to unlock tx.
	stakingOutputAsInput.Sequence = uint32(lockTime)

	spendTx := wire.NewMsgTx(2)
	spendTx.AddTxIn(stakingOutputAsInput)
	spendTx.AddTxOut(newOutput)

	// transaction have 1 P2TR input and does not have any change
	txSize := txsizes.EstimateVirtualSize(0, 1, 0, 0, []*wire.TxOut{newOutput}, 0)

	fee := txrules.FeeForSerializeSize(btcutil.Amount(feeRate), txSize)

	spendTx.TxOut[0].Value = spendTx.TxOut[0].Value - int64(fee)

	if spendTx.TxOut[0].Value <= 0 {
		return nil, nil, fmt.Errorf("too big fee rate for spend stake tx. calculated fee: %d. funding output value: %d", fee, fundingOutput.Value)
	}

	return spendTx, &fee, nil
}

func createSpendStakeTxFromStoredTx(
	storedtx *stakerdb.StoredTransaction,
	destinationScript []byte,
	feeRate chainfee.SatPerKVByte,
) (*spendStakeTxInfo, error) {
	if storedtx.State == proto.TransactionState_SENT_TO_BABYLON {
		parsedScript, err := staking.ParseStakingTransactionScript(storedtx.TxScript)

		if err != nil {
			return nil, fmt.Errorf("invalid staking transaction script in provides staking transaction: %w", err)
		}

		stakingTxHash := storedtx.StakingTx.TxHash()
		// transaction is only in sent to babylon state we try to spend staking output directly
		spendTx, calculatedFee, err := createSpendStakeTx(
			destinationScript,
			storedtx.StakingTx.TxOut[storedtx.StakingOutputIndex],
			storedtx.StakingOutputIndex,
			&stakingTxHash,
			parsedScript.StakingTime,
			feeRate,
		)

		if err != nil {
			return nil, err
		}

		return &spendStakeTxInfo{
			spendStakeTx:        spendTx,
			fundingOutputScript: storedtx.TxScript,
			fundingOutput:       storedtx.StakingTx.TxOut[storedtx.StakingOutputIndex],
			calculatedFee:       *calculatedFee,
		}, nil
	} else if storedtx.State == proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC {

		data := storedtx.UnbondingTxData

		unbondingTxHash := data.UnbondingTx.TxHash()

		parsedScript, err := staking.ParseStakingTransactionScript(data.UnbondingTxScript)

		if err != nil {
			return nil, fmt.Errorf("invalid staking transaction script in provided unbonding transaction: %w", err)
		}

		spendTx, calculatedFee, err := createSpendStakeTx(
			destinationScript,
			// unbonding tx has only one output
			data.UnbondingTx.TxOut[0],
			0,
			&unbondingTxHash,
			parsedScript.StakingTime,
			feeRate,
		)
		if err != nil {
			return nil, err
		}

		return &spendStakeTxInfo{
			spendStakeTx:        spendTx,
			fundingOutput:       data.UnbondingTx.TxOut[0],
			fundingOutputScript: data.UnbondingTxScript,
			calculatedFee:       *calculatedFee,
		}, nil
	} else {
		return nil, fmt.Errorf("cannot build spend stake transactions.Staking transaction is in invalid state: %s", storedtx.State)
	}
}
