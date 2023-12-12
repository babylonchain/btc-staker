package staker

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"

	sdkmath "cosmossdk.io/math"
	staking "github.com/babylonchain/babylon/btcstaking"

	bbn "github.com/babylonchain/babylon/types"
	cl "github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/proto"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

type spendStakeTxInfo struct {
	spendStakeTx           *wire.MsgTx
	fundingOutput          *wire.TxOut
	fundingOutputSpendInfo *staking.SpendInfo
	calculatedFee          btcutil.Amount
}

// babylonPopToDbPop receives already validated pop from external sources and converts it to database representation
func babylonPopToDbPop(pop *cl.BabylonPop) *stakerdb.ProofOfPossession {
	return &stakerdb.ProofOfPossession{
		BtcSigType:           pop.PopTypeNum(),
		BabylonSigOverBtcPk:  pop.BabylonEcdsaSigOverBtcPk,
		BtcSigOverBabylonSig: pop.BtcSig,
	}
}

func babylonCovSigToDbCovSig(covSig cl.CovenantSignatureInfo) stakerdb.PubKeySigPair {
	return stakerdb.NewCovenantMemberSignature(covSig.Signature, covSig.PubKey)
}

func babylonCovSigsToDbSigSigs(covSigs []cl.CovenantSignatureInfo) []stakerdb.PubKeySigPair {
	sigSigs := make([]stakerdb.PubKeySigPair, len(covSigs))

	for i := range covSigs {
		sigSigs[i] = babylonCovSigToDbCovSig(covSigs[i])
	}

	return sigSigs
}

// Helper function to sort all signatures in reverse lexicographical order of signing public keys
// this way signatures are ready to be used in multisig witness with corresponding public keys
func sortPubKeysForWitness(infos []*btcec.PublicKey) []*btcec.PublicKey {
	sortedInfos := make([]*btcec.PublicKey, len(infos))
	copy(sortedInfos, infos)
	sort.SliceStable(sortedInfos, func(i, j int) bool {
		keyIBytes := schnorr.SerializePubKey(sortedInfos[i])
		keyJBytes := schnorr.SerializePubKey(sortedInfos[j])
		return bytes.Compare(keyIBytes, keyJBytes) == 1
	})

	return sortedInfos
}

func pubKeyToString(pubKey *btcec.PublicKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(pubKey))
}

func createWitnessSignaturesForPubKeys(
	covenantPubKeys []*btcec.PublicKey,
	receivedSignaturePairs []stakerdb.PubKeySigPair,
) []*schnorr.Signature {
	// create map of received signatures
	receivedSignatures := make(map[string]*schnorr.Signature)

	for _, pair := range receivedSignaturePairs {
		receivedSignatures[pubKeyToString(pair.PubKey)] = pair.Signature
	}

	sortedPubKeys := sortPubKeysForWitness(covenantPubKeys)

	// this makes sure number of signatures is equal to number of public keys
	signatures := make([]*schnorr.Signature, len(sortedPubKeys))

	for i, key := range sortedPubKeys {
		k := key
		if signature, found := receivedSignatures[pubKeyToString(k)]; found {
			signatures[i] = signature
		}
	}

	return signatures
}

func buildSlashingTxAndSig(
	delegationData *externalDelegationData,
	storedTx *stakerdb.StoredTransaction,
	net *chaincfg.Params,
) (*wire.MsgTx, *schnorr.Signature, error) {

	slashingTx, err := staking.BuildSlashingTxFromStakingTx(
		storedTx.StakingTx,
		storedTx.StakingOutputIndex,
		delegationData.slashingAddress, delegationData.slashingTxChangeAddress,
		delegationData.slashingRate,
		int64(delegationData.slashingFee),
	)

	if err != nil {
		return nil, nil, fmt.Errorf("buidling slashing transaction failed: %w", err)
	}

	stakingInfo, err := staking.BuildStakingInfo(
		delegationData.stakerPrivKey.PubKey(),
		storedTx.ValidatorBtcPks,
		delegationData.covenantPks,
		delegationData.covenantThreshold,
		storedTx.StakingTime,
		btcutil.Amount(storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex].Value),
		net,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("building staking info failed: %w", err)
	}

	slashingPathInfo, err := stakingInfo.SlashingPathSpendInfo()

	if err != nil {
		return nil, nil, fmt.Errorf("building slashing path info failed: %w", err)
	}

	slashingTxSignature, err := staking.SignTxWithOneScriptSpendInputFromScript(
		slashingTx,
		storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex],
		delegationData.stakerPrivKey,
		slashingPathInfo.RevealedLeaf.Script,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("signing slashing transaction failed: %w", err)
	}

	return slashingTx, slashingTxSignature, nil
}

func createDelegationData(
	StakerBtcPk *btcec.PublicKey,
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
		StakingTransactionInclusionProof:     stakingTxInclusionProof,
		StakingTransactionInclusionBlockHash: &inclusionBlockHash,
		StakingTime:                          storedTx.StakingTime,
		StakingValue:                         btcutil.Amount(storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex].Value),
		ValidatorBtcPks:                      storedTx.ValidatorBtcPks,
		StakerBtcPk:                          StakerBtcPk,
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
	stakerBtcPk *btcec.PublicKey,
	covenantPublicKeys []*btcec.PublicKey,
	covenantThreshold uint32,
	storedtx *stakerdb.StoredTransaction,
	destinationScript []byte,
	feeRate chainfee.SatPerKVByte,
	net *chaincfg.Params,
) (*spendStakeTxInfo, error) {
	if storedtx.State == proto.TransactionState_SENT_TO_BABYLON {
		stakingInfo, err := staking.BuildStakingInfo(
			stakerBtcPk,
			storedtx.ValidatorBtcPks,
			covenantPublicKeys,
			covenantThreshold,
			storedtx.StakingTime,
			btcutil.Amount(storedtx.StakingTx.TxOut[storedtx.StakingOutputIndex].Value),
			net,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to build staking info while spending staking transaction: %w", err)
		}

		stakingTimeLockPathInfo, err := stakingInfo.TimeLockPathSpendInfo()

		if err != nil {
			return nil, fmt.Errorf("failed to build time lock path info while spending staking transaction: %w", err)
		}

		stakingTxHash := storedtx.StakingTx.TxHash()
		// transaction is only in sent to babylon state we try to spend staking output directly
		spendTx, calculatedFee, err := createSpendStakeTx(
			destinationScript,
			storedtx.StakingTx.TxOut[storedtx.StakingOutputIndex],
			storedtx.StakingOutputIndex,
			&stakingTxHash,
			storedtx.StakingTime,
			feeRate,
		)

		if err != nil {
			return nil, err
		}

		return &spendStakeTxInfo{
			spendStakeTx:           spendTx,
			fundingOutputSpendInfo: stakingTimeLockPathInfo,
			fundingOutput:          storedtx.StakingTx.TxOut[storedtx.StakingOutputIndex],
			calculatedFee:          *calculatedFee,
		}, nil
	} else if storedtx.State == proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC {
		data := storedtx.UnbondingTxData

		unbondingInfo, err := staking.BuildUnbondingInfo(
			stakerBtcPk,
			storedtx.ValidatorBtcPks,
			covenantPublicKeys,
			covenantThreshold,
			data.UnbondingTime,
			btcutil.Amount(data.UnbondingTx.TxOut[0].Value),
			net,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to build staking info while spending unbonding transaction: %w", err)
		}

		unbondingTimeLockPathInfo, err := unbondingInfo.TimeLockPathSpendInfo()

		if err != nil {
			return nil, fmt.Errorf("failed to build time lock path info while spending unbonding transaction: %w", err)
		}

		unbondingTxHash := data.UnbondingTx.TxHash()

		spendTx, calculatedFee, err := createSpendStakeTx(
			destinationScript,
			// unbonding tx has only one output
			data.UnbondingTx.TxOut[0],
			0,
			&unbondingTxHash,
			data.UnbondingTime,
			feeRate,
		)
		if err != nil {
			return nil, err
		}

		return &spendStakeTxInfo{
			spendStakeTx:           spendTx,
			fundingOutput:          data.UnbondingTx.TxOut[0],
			fundingOutputSpendInfo: unbondingTimeLockPathInfo,
			calculatedFee:          *calculatedFee,
		}, nil
	} else {
		return nil, fmt.Errorf("cannot build spend stake transactions.Staking transaction is in invalid state: %s", storedtx.State)
	}
}

func createUndelegationData(
	storedTx *stakerdb.StoredTransaction,
	stakerPrivKey *btcec.PrivateKey,
	covenantPubKeys []*btcec.PublicKey,
	covenantThreshold uint32,
	slashingAddress, slashingTxChangeAddress btcutil.Address,
	feeRatePerKb btcutil.Amount,
	finalizationTimeBlocks uint16,
	slashingFee btcutil.Amount,
	slashingRate sdkmath.LegacyDec,
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

	unbondingTime := finalizationTimeBlocks + 1

	unbondingInfo, err := staking.BuildUnbondingInfo(
		stakerPrivKey.PubKey(),
		storedTx.ValidatorBtcPks,
		covenantPubKeys,
		covenantThreshold,
		unbondingTime,
		btcutil.Amount(unbondingOutputValue),
		btcNetwork,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to build unbonding data: %w", err)
	}

	unbondingTx := wire.NewMsgTx(2)
	unbondingTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&stakingTxHash, storedTx.StakingOutputIndex), nil, nil))
	unbondingTx.AddTxOut(unbondingInfo.UnbondingOutput)

	slashUnbondingTx, err := staking.BuildSlashingTxFromStakingTxStrict(
		unbondingTx,
		0,
		slashingAddress, slashingTxChangeAddress,
		int64(slashingFee),
		slashingRate,
		btcNetwork,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to build unbonding data: failed to build slashing tx: %w", err)
	}

	slashingPathInfo, err := unbondingInfo.SlashingPathSpendInfo()

	if err != nil {
		return nil, fmt.Errorf("failed to build slashing path info: %w", err)
	}

	slashUnbondingTxSignature, err := staking.SignTxWithOneScriptSpendInputFromScript(
		slashUnbondingTx,
		unbondingInfo.UnbondingOutput,
		stakerPrivKey,
		slashingPathInfo.RevealedLeaf.Script,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to build unbonding data: failed to sign slashing tx: %w", err)
	}

	return &cl.UndelegationData{
		UnbondingTransaction:         unbondingTx,
		UnbondingTxValue:             btcutil.Amount(unbondingOutputValue),
		UnbondingTxUnbondingTime:     unbondingTime,
		SlashUnbondingTransaction:    slashUnbondingTx,
		SlashUnbondingTransactionSig: slashUnbondingTxSignature,
	}, nil
}

func createWitnessToSendUnbondingTx(
	stakerPrivKey *btcec.PrivateKey,
	storedTx *stakerdb.StoredTransaction,
	unbondingData *stakerdb.UnbondingStoreData,
	params *cl.StakingParams,
	net *chaincfg.Params,
) (wire.TxWitness, error) {
	if storedTx.State < proto.TransactionState_UNBONDING_SIGNATURES_RECEIVED {
		return nil, fmt.Errorf("cannot create witness for sending unbonding tx. Staking transaction is in invalid state: %s", storedTx.State)
	}

	if unbondingData.UnbondingTx == nil {
		return nil, fmt.Errorf("cannot create witness for sending unbonding tx. Unbonding data does not contain unbonding transaction")
	}

	if len(unbondingData.CovenantSignatures) < int(params.CovenantQuruomThreshold) {
		return nil, fmt.Errorf("cannot create witness for sending unbonding tx. Unbonding data does not contain all necessary signatures. Required: %d, received: %d", params.CovenantQuruomThreshold, len(unbondingData.CovenantSignatures))
	}

	stakingInfo, err := staking.BuildStakingInfo(
		stakerPrivKey.PubKey(),
		storedTx.ValidatorBtcPks,
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		storedTx.StakingTime,
		btcutil.Amount(storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex].Value),
		net,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to build unbonding data: %w", err)
	}

	unbondingPathInfo, err := stakingInfo.UnbondingPathSpendInfo()

	if err != nil {
		return nil, fmt.Errorf("failed to build unbonding path info: %w", err)
	}

	stakerUnbondingSig, err := staking.SignTxWithOneScriptSpendInputFromScript(
		unbondingData.UnbondingTx,
		storedTx.StakingTx.TxOut[storedTx.StakingOutputIndex],
		stakerPrivKey,
		unbondingPathInfo.RevealedLeaf.Script,
	)

	if err != nil {
		return nil, err
	}

	covenantSigantures := createWitnessSignaturesForPubKeys(
		params.CovenantPks,
		unbondingData.CovenantSignatures,
	)

	return unbondingPathInfo.CreateUnbondingPathWitness(
		covenantSigantures,
		stakerUnbondingSig,
	)
}

func parseWatchStakingRequest(
	stakingTx *wire.MsgTx,
	stakingTime uint16,
	stakingValue btcutil.Amount,
	validatorBtcPks []*btcec.PublicKey,
	slashingTx *wire.MsgTx,
	slashingTxSig *schnorr.Signature,
	stakerBabylonPk *secp256k1.PubKey,
	stakerBtcPk *btcec.PublicKey,
	stakerAddress btcutil.Address,
	pop *cl.BabylonPop,
	currentParams *cl.StakingParams,
	network *chaincfg.Params,
) (*stakingRequestedEvent, error) {
	stakingInfo, err := staking.BuildStakingInfo(
		stakerBtcPk,
		validatorBtcPks,
		currentParams.CovenantPks,
		currentParams.CovenantQuruomThreshold,
		stakingTime,
		stakingValue,
		network,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx due to invalid staking info: %w", err)
	}

	stakingOutputIdx, err := bbn.GetOutputIdxInBTCTx(stakingTx, stakingInfo.StakingOutput)

	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx due to tx not matching current data: %w", err)
	}

	// 2. Check wheter slashing tx match staking tx
	err = staking.CheckTransactions(
		slashingTx,
		stakingTx,
		stakingOutputIdx,
		int64(currentParams.MinSlashingTxFeeSat),
		currentParams.SlashingRate,
		currentParams.SlashingAddress,
		network,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid transactions: %w", err)
	}

	stakingTxSlashingPathInfo, err := stakingInfo.SlashingPathSpendInfo()

	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid staking path info: %w", err)
	}

	// 4. Check slashig tx sig is good. It implicitly verify staker pubkey, as script
	// contain it.
	err = staking.VerifyTransactionSigWithOutputData(
		slashingTx,
		stakingTx.TxOut[stakingOutputIdx].PkScript,
		stakingTx.TxOut[stakingOutputIdx].Value,
		stakingTxSlashingPathInfo.RevealedLeaf.Script,
		stakerBtcPk,
		slashingTxSig.Serialize(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid slashing tx sig: %w", err)
	}

	// 5. Validate pop
	if err = pop.ValidatePop(stakerBabylonPk, stakerBtcPk, network); err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid pop: %w", err)
	}

	// 6. Extract slashing tx change address
	_, outAddrs, _, err := txscript.ExtractPkScriptAddrs(slashingTx.TxOut[1].PkScript, network)
	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid slashing tx change address: %w", err)
	}
	if len(outAddrs) != 1 {
		return nil, fmt.Errorf("failed to watch staking tx. Only one slashing tx change address is allowed")
	}
	slashingTxChangeAddress := outAddrs[0]

	req := newWatchedStakingRequest(
		stakerAddress, slashingTxChangeAddress,
		stakingTx,
		uint32(stakingOutputIdx),
		stakingTx.TxOut[stakingOutputIdx].PkScript,
		stakingTime,
		stakingValue,
		validatorBtcPks,
		currentParams.ConfirmationTimeBlocks,
		pop,
		slashingTx,
		slashingTxSig,
		stakerBabylonPk,
		stakerBtcPk,
	)

	return req, nil
}

func haveDuplicates(btcPKs []*btcec.PublicKey) bool {
	seen := make(map[string]struct{})

	for _, btcPK := range btcPKs {
		pkStr := hex.EncodeToString(schnorr.SerializePubKey(btcPK))

		if _, found := seen[pkStr]; found {
			return true
		} else {
			seen[pkStr] = struct{}{}
		}
	}

	return false
}
