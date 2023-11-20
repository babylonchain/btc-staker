package staker

import (
	cl "github.com/babylonchain/btc-staker/babylonclient"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/sirupsen/logrus"
)

type StakingEvent interface {
	// Each staking event is identified by initial staking transaction hash
	EventId() chainhash.Hash
	EventDesc() string
}

var _ StakingEvent = (*stakingRequestedEvent)(nil)
var _ StakingEvent = (*stakingTxBtcConfirmedEvent)(nil)
var _ StakingEvent = (*delegationSubmittedToBabylonEvent)(nil)
var _ StakingEvent = (*undelegationSubmittedToBabylonEvent)(nil)
var _ StakingEvent = (*unbondingTxSignaturesConfirmedOnBabylonEvent)(nil)
var _ StakingEvent = (*unbondingTxConfirmedOnBtcEvent)(nil)
var _ StakingEvent = (*spendStakeTxConfirmedOnBtcEvent)(nil)
var _ StakingEvent = (*criticalErrorEvent)(nil)

type stakingRequestedEvent struct {
	stakerAddress           btcutil.Address
	changeAddress           btcutil.Address
	stakingTxHash           chainhash.Hash
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
	stakerAddress, changeAddress btcutil.Address,
	stakingTx *wire.MsgTx,
	stakingOutputIdx uint32,
	stakingOutputPkScript []byte,
	stakingScript []byte,
	confirmationTimeBlocks uint32,
	pop *cl.BabylonPop,
) *stakingRequestedEvent {
	return &stakingRequestedEvent{
		stakerAddress:           stakerAddress,
		changeAddress:           changeAddress,
		stakingTxHash:           stakingTx.TxHash(),
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
		stakingTxHash:           stakingTx.TxHash(),
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

func (req *stakingRequestedEvent) EventId() chainhash.Hash {
	return req.stakingTxHash
}

func (req *stakingRequestedEvent) EventDesc() string {
	return "STAKING_REQUESTED"
}

type stakingTxBtcConfirmedEvent struct {
	stakingTxHash chainhash.Hash
	txIndex       uint32
	blockDepth    uint32
	blockHash     chainhash.Hash
	blockHeight   uint32
	tx            *wire.MsgTx
	inlusionBlock *wire.MsgBlock
}

func (event *stakingTxBtcConfirmedEvent) EventId() chainhash.Hash {
	return event.stakingTxHash
}

func (event *stakingTxBtcConfirmedEvent) EventDesc() string {
	return "STAKING_TX_BTC_CONFIRMED"
}

type delegationSubmittedToBabylonEvent struct {
	stakingTxHash chainhash.Hash
}

func (event *delegationSubmittedToBabylonEvent) EventId() chainhash.Hash {
	return event.stakingTxHash
}

func (event *delegationSubmittedToBabylonEvent) EventDesc() string {
	return "DELEGATION_SUBMITTED_TO_BABYLON"
}

type undelegationSubmittedToBabylonEvent struct {
	stakingTxHash              chainhash.Hash
	unbondingTransaction       *wire.MsgTx
	unbondingTransactionScript []byte
	successChan                chan *chainhash.Hash
}

func (event *undelegationSubmittedToBabylonEvent) EventId() chainhash.Hash {
	return event.stakingTxHash
}

func (event *undelegationSubmittedToBabylonEvent) EventDesc() string {
	return "UNDELEGATION_SUBMITTED_TO_BABYLON"
}

type unbondingTxSignaturesConfirmedOnBabylonEvent struct {
	stakingTxHash               chainhash.Hash
	juryUnbondingSignature      *schnorr.Signature
	validatorUnbondingSignature *schnorr.Signature
}

func (event *unbondingTxSignaturesConfirmedOnBabylonEvent) EventId() chainhash.Hash {
	return event.stakingTxHash
}

func (event *unbondingTxSignaturesConfirmedOnBabylonEvent) EventDesc() string {
	return "UNBONDING_TX_SIGNATURES_CONFIRMED_ON_BABYLON"
}

type unbondingTxConfirmedOnBtcEvent struct {
	stakingTxHash chainhash.Hash
	blockHash     chainhash.Hash
	blockHeight   uint32
}

func (event *unbondingTxConfirmedOnBtcEvent) EventId() chainhash.Hash {
	return event.stakingTxHash
}

func (event *unbondingTxConfirmedOnBtcEvent) EventDesc() string {
	return "UNBONDING_TX_CONFIRMED_ON_BTC"
}

type spendStakeTxConfirmedOnBtcEvent struct {
	stakingTxHash chainhash.Hash
}

func (event *spendStakeTxConfirmedOnBtcEvent) EventId() chainhash.Hash {
	return event.stakingTxHash
}

func (event *spendStakeTxConfirmedOnBtcEvent) EventDesc() string {
	return "SPEND_STAKE_TX_CONFIRMED_ON_BTC"
}

type criticalErrorEvent struct {
	stakingTxHash     chainhash.Hash
	err               error
	additionalContext string
}

func (event *criticalErrorEvent) EventId() chainhash.Hash {
	return event.stakingTxHash
}

func (event *criticalErrorEvent) EventDesc() string {
	return "CRITICAL_ERROR"
}

func (app *StakerApp) logStakingEventReceived(event StakingEvent) {
	app.logger.WithFields(logrus.Fields{
		"eventId": event.EventId(),
		"event":   event.EventDesc(),
	}).Debug("Received staking event")
}

func (app *StakerApp) logStakingEventProcessed(event StakingEvent) {
	app.logger.WithFields(logrus.Fields{
		"eventId": event.EventId(),
		"event":   event.EventDesc(),
	}).Debug("Processed staking event")
}
