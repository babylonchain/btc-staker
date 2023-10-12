package staker

import (
	cl "github.com/babylonchain/btc-staker/babylonclient"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

type stakingRequestedEvent struct {
	stakerAddress           btcutil.Address
	stakingTx               *wire.MsgTx
	stakingOutputIdx        uint32
	stakingOutputPkScript   []byte
	stakingTxScript         []byte
	requiredDepthOnBtcChain uint32
	pop                     *cl.BabylonPop
	watchTxData             *watchTxData
	errChan                 chan error
	successChan             chan *chainhash.Hash
}

func (req *stakingRequestedEvent) isWatched() bool {
	return req.watchTxData != nil
}

func newOwnedStakingRequest(
	stakerAddress btcutil.Address,
	stakingTx *wire.MsgTx,
	stakingOutputIdx uint32,
	stakingOutputPkScript []byte,
	stakingScript []byte,
	confirmationTimeBlocks uint32,
	pop *cl.BabylonPop,
) *stakingRequestedEvent {
	return &stakingRequestedEvent{
		stakerAddress:           stakerAddress,
		stakingTx:               stakingTx,
		stakingOutputIdx:        stakingOutputIdx,
		stakingOutputPkScript:   stakingOutputPkScript,
		stakingTxScript:         stakingScript,
		requiredDepthOnBtcChain: confirmationTimeBlocks,
		pop:                     pop,
		watchTxData:             nil,
		errChan:                 make(chan error, 1),
		successChan:             make(chan *chainhash.Hash, 1),
	}
}

type watchTxData struct {
	slashingTx          *wire.MsgTx
	slashingTxSig       *schnorr.Signature
	stakerBabylonPubKey *secp256k1.PubKey
}

func newWatchedStakingRequest(
	stakerAddress btcutil.Address,
	stakingTx *wire.MsgTx,
	stakingOutputIdx uint32,
	stakingOutputPkScript []byte,
	stakingScript []byte,
	confirmationTimeBlocks uint32,
	pop *cl.BabylonPop,
	slashingTx *wire.MsgTx,
	slashingTxSignature *schnorr.Signature,
	stakerBabylonPubKey *secp256k1.PubKey,
) *stakingRequestedEvent {
	return &stakingRequestedEvent{
		stakerAddress:           stakerAddress,
		stakingTx:               stakingTx,
		stakingOutputIdx:        stakingOutputIdx,
		stakingOutputPkScript:   stakingOutputPkScript,
		stakingTxScript:         stakingScript,
		requiredDepthOnBtcChain: confirmationTimeBlocks,
		pop:                     pop,
		watchTxData: &watchTxData{
			slashingTx:          slashingTx,
			slashingTxSig:       slashingTxSignature,
			stakerBabylonPubKey: stakerBabylonPubKey,
		},
		errChan:     make(chan error, 1),
		successChan: make(chan *chainhash.Hash, 1),
	}
}

type stakingTxBtcConfirmedEvent struct {
	txHash        chainhash.Hash
	txIndex       uint32
	blockDepth    uint32
	blockHash     chainhash.Hash
	blockHeight   uint32
	tx            *wire.MsgTx
	inlusionBlock *wire.MsgBlock
}

type delegationSubmissionResultEvent struct {
	txHash *chainhash.Hash
	err    error
}

type undelegationSubmittedToBabylonEvent struct {
	stakingTxHash              chainhash.Hash
	unbondingTransaction       *wire.MsgTx
	unbondingTransactionScript []byte
	successChan                chan *chainhash.Hash
}

type unbondingTxSignaturesConfirmedOnBabylonEvent struct {
	stakingTxHash               chainhash.Hash
	juryUnbondingSignature      *schnorr.Signature
	validatorUnbondingSignature *schnorr.Signature
}

type unbondingTxConfirmedOnBtcEvent struct {
	stakingTxHash chainhash.Hash
	blockHash     chainhash.Hash
	blockHeight   uint32
}

type spendStakeTxConfirmedOnBtcEvent struct {
	stakingTxHash chainhash.Hash
}
