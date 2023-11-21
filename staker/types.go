package staker

import (
	"bytes"
	"fmt"

	staking "github.com/babylonchain/babylon/btcstaking"
	sdk "github.com/cosmos/cosmos-sdk/types"

	cl "github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/proto"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
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
		BtcSigType:           pop.PopTypeNum(),
		BabylonSigOverBtcPk:  pop.BabylonEcdsaSigOverBtcPk,
		BtcSigOverBabylonSig: pop.BtcSig,
	}
}

func buildSlashingTxAndSig(
	delegationData *externalDelegationData,
	storedTx *stakerdb.StoredTransaction,
) (*wire.MsgTx, *schnorr.Signature, error) {

	slashingTx, err := staking.BuildSlashingTxFromStakingTx(
		storedTx.StakingTx,
		storedTx.StakingOutputIndex,
		delegationData.slashingAddress, delegationData.changeAddress,
		delegationData.slashingRate,
		int64(delegationData.slashingFee),
	)

	if err != nil {
		return nil, nil, fmt.Errorf("buidling slashing transaction failed: %w", err)
	}

	slashingTxSignature, err := staking.SignTxWithOneScriptSpendInputFromScript(
		slashingTx,
		storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex],
		delegationData.stakerPrivKey,
		storedTx.TxScript,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("signing slashing transaction failed: %w", err)
	}

	return slashingTx, slashingTxSignature, nil
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

func createUndelegationData(
	storedTx *stakerdb.StoredTransaction,
	stakerPrivKey *btcec.PrivateKey,
	covenantPubKey *btcec.PublicKey,
	slashingAddress, changeAddress btcutil.Address,
	feeRatePerKb btcutil.Amount,
	finalizationTimeBlocks uint16,
	slashingFee btcutil.Amount,
	slashingRate sdk.Dec,
	stakingScriptData *staking.StakingScriptData,
	btcNetwork *chaincfg.Params,
) (*cl.UndelegationData, error) {
	stakingTxHash := storedTx.StakingTx.TxHash()

	stakingOutpout := storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex]

	unbondingTxFee := txrules.FeeForSerializeSize(feeRatePerKb, slashingPathSpendTxVSize)

	unbondingOutputValue := stakingOutpout.Value - int64(unbondingTxFee)

	if unbondingOutputValue <= 0 {
		return nil, fmt.Errorf(
			"too large fee rate %d sats/kb. Staking output value:%d sats. Unbonding tx fee:%d sats", int64(feeRatePerKb), stakingOutpout.Value, int64(unbondingTxFee),
		)
	}

	if unbondingOutputValue <= int64(slashingFee) {
		return nil, fmt.Errorf(
			"too large fee rate %d sats/kb. Unbonding output value %d sats. Slashing tx fee: %d sats", int64(feeRatePerKb), unbondingOutputValue, int64(slashingFee),
		)
	}

	// unbonding output script is the same as staking output (usually it will have lower staking time)
	unbondingOutput, unbondingScript, err := staking.BuildStakingOutput(
		stakingScriptData.StakerKey,
		stakingScriptData.ValidatorKey,
		covenantPubKey,
		finalizationTimeBlocks+1,
		btcutil.Amount(unbondingOutputValue),
		btcNetwork,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to build unbonding output: %w", err)
	}

	unbondingTx := wire.NewMsgTx(2)
	unbondingTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&stakingTxHash, storedTx.StakingOutputIndex), nil, nil))
	unbondingTx.AddTxOut(unbondingOutput)

	slashUnbondingTx, err := staking.BuildSlashingTxFromStakingTxStrict(
		unbondingTx,
		0,
		slashingAddress, changeAddress,
		int64(slashingFee),
		slashingRate,
		unbondingScript,
		btcNetwork,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to build unbonding data: failed to build slashing tx: %w", err)
	}

	slashUnbondingTxSignature, err := staking.SignTxWithOneScriptSpendInputFromScript(
		slashUnbondingTx,
		unbondingOutput,
		stakerPrivKey, unbondingScript,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to build unbonding data: failed to sign slashing tx: %w", err)
	}

	return &cl.UndelegationData{
		UnbondingTransaction:         unbondingTx,
		UnbondingTransactionScript:   unbondingScript,
		SlashUnbondingTransaction:    slashUnbondingTx,
		SlashUnbondingTransactionSig: slashUnbondingTxSignature,
	}, nil
}

func createWitnessToSendUnbondingTx(
	stakerPrivKey *btcec.PrivateKey,
	storedTx *stakerdb.StoredTransaction,
	unbondingData *stakerdb.UnbondingStoreData,
) (wire.TxWitness, error) {
	if storedTx.State < proto.TransactionState_UNBONDING_SIGNATURES_RECEIVED {
		return nil, fmt.Errorf("cannot create witness for sending unbonding tx. Staking transaction is in invalid state: %s", storedTx.State)
	}

	if unbondingData.UnbondingTx == nil {
		return nil, fmt.Errorf("cannot create witness for sending unbonding tx. Unbonding data does not contain unbonding transaction")
	}

	if unbondingData.UnbondingTxCovenantSignature == nil || unbondingData.UnbondingTxValidatorSignature == nil {
		return nil, fmt.Errorf("cannot create witness for sending unbonding tx. Unbonding data does not contain all necessary signatures")
	}

	stakerUnbondingSig, err := staking.SignTxWithOneScriptSpendInputFromScript(
		unbondingData.UnbondingTx,
		storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex],
		stakerPrivKey,
		storedTx.TxScript,
	)

	if err != nil {
		return nil, err
	}

	stakerWitness, err := staking.NewWitnessFromStakingScriptAndSignature(
		storedTx.TxScript,
		stakerUnbondingSig,
	)

	if err != nil {
		return nil, err
	}

	// Build valid wittness for spending staking output with all signatures
	witnessStack := wire.TxWitness(make([][]byte, 6))
	witnessStack[0] = unbondingData.UnbondingTxCovenantSignature.Serialize()
	witnessStack[1] = unbondingData.UnbondingTxValidatorSignature.Serialize()
	witnessStack[2] = stakerWitness[0]
	witnessStack[3] = []byte{}
	witnessStack[4] = stakerWitness[1]
	witnessStack[5] = stakerWitness[2]

	return witnessStack, nil
}

func parseWatchStakingRequest(
	stakingTx *wire.MsgTx,
	stakingscript []byte,
	slashingTx *wire.MsgTx,
	slashingTxSig *schnorr.Signature,
	stakerBabylonPk *secp256k1.PubKey,
	stakerAddress, changeAddress btcutil.Address,
	pop *cl.BabylonPop,
	currentParams *cl.StakingParams,
	network *chaincfg.Params,
) (*stakingRequestedEvent, *staking.StakingScriptData, error) {
	// 1. Check script matches transaction
	stakingOutputIdx, err := staking.GetIdxOutputCommitingToScript(
		stakingTx,
		stakingscript,
		network,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to watch staking tx due to script not matchin script: %w", err)
	}

	// 2. Check wheter slashing tx match staking tx
	scriptData, err := staking.CheckTransactions(
		slashingTx,
		stakingTx,
		int64(currentParams.MinSlashingTxFeeSat),
		currentParams.SlashingRate,
		currentParams.SlashingAddress,
		stakingscript,
		network,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to watch staking tx. Invalid transactions: %w", err)
	}

	// 3.Check jury key in script
	if !bytes.Equal(
		schnorr.SerializePubKey(scriptData.StakingScriptData.CovenantKey),
		schnorr.SerializePubKey(&currentParams.CovenantPk),
	) {
		return nil, nil, fmt.Errorf("failed to watch staking tx. Script jury key do not match current node params")
	}

	// 4. Check slashig tx sig is good. It implicitly verify staker pubkey, as script
	// contain it.
	err = staking.VerifyTransactionSigWithOutputData(
		slashingTx,
		stakingTx.TxOut[stakingOutputIdx].PkScript,
		stakingTx.TxOut[stakingOutputIdx].Value,
		stakingscript,
		scriptData.StakingScriptData.StakerKey,
		slashingTxSig.Serialize(),
	)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to watch staking tx. Invalid slashing tx sig: %w", err)
	}

	// 5. Validate pop
	if err = pop.ValidatePop(stakerBabylonPk, scriptData.StakingScriptData.StakerKey, network); err != nil {
		return nil, nil, fmt.Errorf("failed to watch staking tx. Invalid pop: %w", err)
	}

	req := newWatchedStakingRequest(
		stakerAddress, changeAddress,
		stakingTx,
		uint32(stakingOutputIdx),
		stakingTx.TxOut[stakingOutputIdx].PkScript,
		stakingscript,
		currentParams.ConfirmationTimeBlocks,
		pop,
		slashingTx,
		slashingTxSig,
		stakerBabylonPk,
	)

	return req, scriptData.StakingScriptData, nil
}
