package staker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	staking "github.com/babylonchain/babylon/btcstaking"
	cl "github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/proto"
	scfg "github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/babylonchain/btc-staker/types"
	"github.com/babylonchain/btc-staker/walletcontroller"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	notifier "github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/sirupsen/logrus"
)

type watchTxData struct {
	slashingTx          *wire.MsgTx
	slashingTxSig       *schnorr.Signature
	stakerBabylonPubKey *secp256k1.PubKey
}

type stakingRequest struct {
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

func newOwnedStakingRequest(
	stakerAddress btcutil.Address,
	stakingTx *wire.MsgTx,
	stakingOutputIdx uint32,
	stakingOutputPkScript []byte,
	stakingScript []byte,
	confirmationTimeBlocks uint32,
	pop *cl.BabylonPop,
) *stakingRequest {
	return &stakingRequest{
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
) *stakingRequest {
	return &stakingRequest{
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

type unbondingRequest struct {
	stakingTxHash chainhash.Hash
	unbondingData *cl.UndelegationData
	errChan       chan error
	successChan   chan *chainhash.Hash
}

func newUnbondingRequest(
	stakingTxHash chainhash.Hash,
	unbondingData *cl.UndelegationData) *unbondingRequest {
	return &unbondingRequest{
		stakingTxHash: stakingTxHash,
		unbondingData: unbondingData,
		errChan:       make(chan error, 1),
		successChan:   make(chan *chainhash.Hash, 1),
	}
}

type unbondingRequestConfirm struct {
	stakingTxHash              chainhash.Hash
	unbondingTransaction       *wire.MsgTx
	unbondingTransactionScript []byte
	successChan                chan *chainhash.Hash
}

func (req *stakingRequest) isWatched() bool {
	return req.watchTxData != nil
}

type unbondingSignaturesConfirmed struct {
	stakingTxHash               chainhash.Hash
	juryUnbondingSignature      *schnorr.Signature
	validatorUnbondingSignature *schnorr.Signature
}

type unbondingConfirmedOnBtc struct {
	stakingTxHash chainhash.Hash
}

type confirmationEvent struct {
	txHash        chainhash.Hash
	txIndex       uint32
	blockDepth    uint32
	blockHash     chainhash.Hash
	blockHeight   uint32
	tx            *wire.MsgTx
	inlusionBlock *wire.MsgBlock
}

type sendDelegationRequest struct {
	txHash                      chainhash.Hash
	txIndex                     uint32
	inlusionBlock               *wire.MsgBlock
	requiredInclusionBlockDepth uint64
}

type sendDelegationResponse struct {
	txHash *chainhash.Hash
	err    error
}

type spendTxConfirmationEvent struct {
	stakingTxHash chainhash.Hash
}

type externalDelegationData struct {
	// stakerPrivKey needs to be retrieved from btc wallet
	stakerPrivKey *btcec.PrivateKey
	// slashingAddress needs to be retrieved from babylon
	slashingAddress btcutil.Address

	// babylonPubKey needs to be retrieved from babylon keyring
	babylonPubKey *secp256k1.PubKey

	slashingFee btcutil.Amount
}

type spendStakeTxInfo struct {
	spendStakeTx        *wire.MsgTx
	fundingOutput       *wire.TxOut
	fundingOutputScript []byte
	calculatedFee       btcutil.Amount
}

type stakingDbInfo struct {
	stakingTxHash  *chainhash.Hash
	stakingTxState proto.TransactionState
}

type Delegation struct {
	StakingTxHash string
	State         proto.TransactionState
}

const (
	// Internal slashing fee to adjust to in case babylon provide too small fee
	// Slashing tx is around 113 bytes (depending on output address which we need to chose), with fee 8sats/b
	// this gives us 904 satoshi fee. Lets round it 1000 satoshi
	minSlashingFee = btcutil.Amount(1000)

	// maximum number of delegations that can be pending (waiting to be sent to babylon)
	// at the same time
	maxNumPendingDelegations = 100

	// after this many confirmations we consider transaction which spends staking tx as
	// confirmed on btc
	SpendStakeTxConfirmations = 3

	// 2 hours seems like a reasonable timeout waiting for spend tx confirmations given
	// probabilistic nature of bitcoin
	timeoutWaitingForSpendConfirmation = 2 * time.Hour

	defaultWalletUnlockTimeout = 15

	// Actual virtual size of transaction which spends staking transaction through slashing
	// path. In reality it highly depends on slashingAddress size:
	// for p2pk - 222vb
	// for p2wpkh - 177vb
	// for p2tr - 189vb
	// We are chosing 180vb as we expect slashing address will be one of the more recent
	// address types.
	// Transaction is quite big as witness to spend is composed of:
	// 1. StakerSig
	// 2. JurySig
	// 3. ValidatorSig
	// 4. StakingScript
	// 5. Taproot control block
	slashingPathSpendTxVSize = 180

	// Set minimum fee to 1 sat/byte, as in standard rules policy
	MinFeePerKb = txrules.DefaultRelayFeePerKb

	// If we fail to send unbonding tx to btc for any reason we will retry in this time
	unbondingSendRetryTimeout = 30 * time.Second

	// after this many confirmations we treat unbonding transaction as confirmed on btc
	// TODO: needs to consolidate what is safe confirmation for different types of transaction
	// as currently we have different values for different types of transactions
	UnbondingTxConfirmations = 6
)

type StakerApp struct {
	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
	quit      chan struct{}

	babylonClient                    cl.BabylonClient
	wc                               walletcontroller.WalletController
	notifier                         notifier.ChainNotifier
	feeEstimator                     FeeEstimator
	network                          *chaincfg.Params
	config                           *scfg.Config
	logger                           *logrus.Logger
	txTracker                        *stakerdb.TrackedTransactionStore
	stakingRequestChan               chan *stakingRequest
	confirmationEventChan            chan *confirmationEvent
	sendDelegationRequestChan        chan *sendDelegationRequest
	sendDelegationResponseChan       chan *sendDelegationResponse
	spendTxConfirmationChan          chan *spendTxConfirmationEvent
	sendUnbondingRequestChan         chan *unbondingRequest
	sendUnbondingRequestConfirmChan  chan *unbondingRequestConfirm
	unbondingSignaturesConfirmedChan chan *unbondingSignaturesConfirmed
	unbondingConfirmedOnBtcChan      chan *unbondingConfirmedOnBtc
	currentBestBlockHeight           atomic.Uint32
}

func NewStakerAppFromConfig(
	config *scfg.Config,
	logger *logrus.Logger,
	db kvdb.Backend,
) (*StakerApp, error) {
	// TODO: If we want to support multiple wallet types, this is most probably the place to decide
	// on concrete implementation
	walletClient, err := walletcontroller.NewRpcWalletController(config)
	if err != nil {
		return nil, err
	}

	tracker, err := stakerdb.NewTrackedTransactionStore(db)

	if err != nil {
		return nil, err
	}

	cl, err := cl.NewBabylonController(config.BabylonConfig, &config.ActiveNetParams, logger)

	if err != nil {
		return nil, err
	}

	hintCache, err := channeldb.NewHeightHintCache(
		channeldb.CacheConfig{
			// TODO: Investigate this option. Lighting docs mention that this is necessary for some edge case
			QueryDisable: false,
		}, db,
	)

	if err != nil {
		return nil, fmt.Errorf("unable to create height hint cache: %v", err)
	}

	nodeNotifier, err := NewNodeBackend(config.BtcNodeBackendConfig, &config.ActiveNetParams, hintCache)

	if err != nil {
		return nil, err
	}

	var feeEstimator FeeEstimator
	switch config.BtcNodeBackendConfig.EstimationMode {
	case types.StaticFeeEstimation:
		feeEstimator = NewStaticBtcFeeEstimator()
	case types.DynamicFeeEstimation:
		feeEstimator, err = NewDynamicBtcFeeEstimator(config.BtcNodeBackendConfig, &config.ActiveNetParams, logger)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown fee estimation mode: %d", config.BtcNodeBackendConfig.EstimationMode)
	}

	return NewStakerAppFromDeps(
		config,
		logger,
		cl,
		walletClient,
		nodeNotifier,
		feeEstimator,
		tracker,
	)
}

func NewStakerAppFromDeps(
	config *scfg.Config,
	logger *logrus.Logger,
	cl cl.BabylonClient,
	walletClient walletcontroller.WalletController,
	nodeNotifier notifier.ChainNotifier,
	feeEestimator FeeEstimator,
	tracker *stakerdb.TrackedTransactionStore,
) (*StakerApp, error) {
	return &StakerApp{
		babylonClient:      cl,
		wc:                 walletClient,
		notifier:           nodeNotifier,
		feeEstimator:       feeEestimator,
		network:            &config.ActiveNetParams,
		txTracker:          tracker,
		config:             config,
		logger:             logger,
		quit:               make(chan struct{}),
		stakingRequestChan: make(chan *stakingRequest),
		// event for when transaction is confirmed on BTC
		confirmationEventChan: make(chan *confirmationEvent),
		// Buffered channels so we do not block receiving confirmations if there is backlog of
		// requests to send to babylon
		sendDelegationRequestChan: make(chan *sendDelegationRequest, maxNumPendingDelegations),

		// event for when delegation is sent to babylon and included in babylon
		sendDelegationResponseChan: make(chan *sendDelegationResponse),

		// event emitted upon transaction which spends staking transaction is confirmed on BTC
		spendTxConfirmationChan: make(chan *spendTxConfirmationEvent),

		// channel for unbonding requests, received from user. Non-buffer so we process
		// at most one request at a time
		sendUnbondingRequestChan: make(chan *unbondingRequest),

		// channel which confirms that unbonding request was sent to babylon, and update
		// correct db state
		sendUnbondingRequestConfirmChan: make(chan *unbondingRequestConfirm),

		// channel which receives unbonding signatures from jury and validator for unbonding
		// transaction
		unbondingSignaturesConfirmedChan: make(chan *unbondingSignaturesConfirmed),

		// channel which receives confirmation that unbonding transaction was confirmed on BTC
		unbondingConfirmedOnBtcChan: make(chan *unbondingConfirmedOnBtc),
	}, nil
}

func (app *StakerApp) Start() error {
	var startErr error
	app.startOnce.Do(func() {
		app.logger.Infof("Starting StakerApp")

		// TODO: This can take a long time as it connects to node. Maybe make it cancellable?
		// although staker without node is not very useful

		app.logger.Infof("Connecting to node backend: %s", app.config.BtcNodeBackendConfig.Nodetype)
		err := app.notifier.Start()
		if err != nil {
			startErr = err
			return
		}

		app.logger.Infof("Successfully connected to node backend: %s", app.config.BtcNodeBackendConfig.Nodetype)

		blockEventNotifier, err := app.notifier.RegisterBlockEpochNtfn(nil)

		if err != nil {
			startErr = err
			return
		}

		// we registered for notifications with `nil`  so we should receive best block
		// immeadiatly
		select {
		case block := <-blockEventNotifier.Epochs:
			app.currentBestBlockHeight.Store(uint32(block.Height))
		case <-app.quit:
			startErr = errors.New("staker app quit before finishing start")
			return
		}

		app.logger.Infof("Initial btc best block height is: %d", app.currentBestBlockHeight.Load())

		app.wg.Add(3)
		go app.handleNewBlocks(blockEventNotifier)
		go app.handleSentToBabylon()
		go app.handleStaking()

		if err := app.checkTransactionsStatus(); err != nil {
			startErr = err
			return
		}
	})

	return startErr
}

func (app *StakerApp) handleNewBlocks(blockNotifier *notifier.BlockEpochEvent) {
	defer app.wg.Done()
	defer blockNotifier.Cancel()
	for {
		select {
		case block, ok := <-blockNotifier.Epochs:
			if !ok {
				return
			}
			app.currentBestBlockHeight.Store(uint32(block.Height))

			app.logger.WithFields(logrus.Fields{
				"btcBlockHeight": block.Height,
				"btcBlockHash":   block.Hash.String(),
			}).Debug("Received new best btc block")
		case <-app.quit:
			return
		}
	}
}

func (app *StakerApp) Stop() error {
	var stopErr error
	app.stopOnce.Do(func() {
		app.logger.Infof("Stopping StakerApp")
		close(app.quit)
		app.wg.Wait()

		err := app.notifier.Stop()
		if err != nil {
			stopErr = err
			return
		}
	})
	return stopErr
}

func (app *StakerApp) waitForStakingTransactionConfirmation(
	stakingTxHash *chainhash.Hash,
	stakingTxPkScript []byte,
	requiredBlockDepth uint32,
	currentBestBlockHeight uint32,
) error {
	app.logger.WithFields(logrus.Fields{
		"stakingTxHash": stakingTxHash.String(),
	}).Debug("Register waiting for tx confirmation")

	confEvent, err := app.notifier.RegisterConfirmationsNtfn(
		stakingTxHash,
		stakingTxPkScript,
		requiredBlockDepth+1,
		currentBestBlockHeight,
		notifier.WithIncludeBlock(),
	)
	if err != nil {
		return err
	}

	go app.waitForStakingTxConfirmation(*stakingTxHash, requiredBlockDepth, confEvent)
	return nil
}

func (app *StakerApp) handleBtcTxInfo(
	stakingTxHash *chainhash.Hash,
	txInfo *stakerdb.StoredTransaction,
	params *cl.StakingParams,
	currentBestBlockHeight uint32,
	txStatus walletcontroller.TxStatus,
	btcTxInfo *notifier.TxConfirmation) error {

	switch txStatus {
	case walletcontroller.TxNotFound:
		// Most probable reason this happened is transaction was included in btc chain (removed from mempool)
		// and wallet also lost data and is not synced far enough to see transaction.
		// Log it as error so that user can investigate.
		// TODO: Set tx to some new state, like `Unknown` and periodically check if it is in mempool or chain ?
		app.logger.WithFields(logrus.Fields{
			"btcTxHash": stakingTxHash,
		}).Error("Transaction from database not found in BTC mempool or chain")
	case walletcontroller.TxInMemPool:
		app.logger.WithFields(logrus.Fields{
			"btcTxHash": stakingTxHash,
		}).Debug("Transaction found in mempool. Stat waiting for confirmation")

		if err := app.waitForStakingTransactionConfirmation(
			stakingTxHash,
			txInfo.BtcTx.TxOut[txInfo.StakingOutputIndex].PkScript,
			params.ConfirmationTimeBlocks,
			currentBestBlockHeight,
		); err != nil {
			return err
		}

	case walletcontroller.TxInChain:
		app.logger.WithFields(logrus.Fields{
			"btcTxHash":              stakingTxHash,
			"btcBlockHeight":         btcTxInfo.BlockHeight,
			"currentBestBlockHeight": currentBestBlockHeight,
		}).Debug("Transaction found in chain")

		if currentBestBlockHeight < btcTxInfo.BlockHeight {
			// This is wierd case, we retrieved transaction from btc wallet, even though wallet best height
			// is lower than block height of transaction.
			// Log it as error so that user can investigate.
			app.logger.WithFields(logrus.Fields{
				"btcTxHash":              stakingTxHash,
				"btcTxBlockHeight":       btcTxInfo.BlockHeight,
				"currentBestBlockHeight": currentBestBlockHeight,
			}).Error("Current best block height is lower than block height of transaction")

			return nil
		}

		blockDepth := currentBestBlockHeight - btcTxInfo.BlockHeight

		if blockDepth >= params.ConfirmationTimeBlocks {
			app.logger.WithFields(logrus.Fields{
				"btcTxHash":              stakingTxHash,
				"btcTxBlockHeight":       btcTxInfo.BlockHeight,
				"currentBestBlockHeight": currentBestBlockHeight,
			}).Debug("Transaction deep enough in btc chain to be sent to Babylon")

			// block is deep enough to init sent to babylon
			app.confirmationEventChan <- &confirmationEvent{
				txHash:        *stakingTxHash,
				txIndex:       btcTxInfo.TxIndex,
				blockDepth:    params.ConfirmationTimeBlocks,
				blockHash:     *btcTxInfo.BlockHash,
				blockHeight:   btcTxInfo.BlockHeight,
				tx:            txInfo.BtcTx,
				inlusionBlock: btcTxInfo.Block,
			}
		} else {
			app.logger.WithFields(logrus.Fields{
				"btcTxHash":              stakingTxHash,
				"btcTxBlockHeight":       btcTxInfo.BlockHeight,
				"currentBestBlockHeight": currentBestBlockHeight,
			}).Debug("Transaction not deep enough in btc chain to be sent to Babylon. Waiting for confirmation")

			if err := app.waitForStakingTransactionConfirmation(
				stakingTxHash,
				txInfo.BtcTx.TxOut[txInfo.StakingOutputIndex].PkScript,
				params.ConfirmationTimeBlocks,
				currentBestBlockHeight,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

// TODO: We should also handle case when btc node or babylon node lost data and start from scratch
// i.e keep track what is last known block height on both chains and detect if after restart
// for some reason they are behind staker
func (app *StakerApp) checkTransactionsStatus() error {
	stakingParams, err := app.babylonClient.Params()

	if err != nil {
		return err
	}

	// Keep track of all staking transactions which need checking. chainhash.Hash objects are not relativly small
	// so it should not OOM even for larage database
	var transactionsSentToBtc []*chainhash.Hash
	var transactionConfirmedOnBtc []*chainhash.Hash
	var transactionsOnBabylon []*stakingDbInfo

	reset := func() {
		transactionsSentToBtc = make([]*chainhash.Hash, 0)
		transactionConfirmedOnBtc = make([]*chainhash.Hash, 0)
		transactionsOnBabylon = make([]*stakingDbInfo, 0)
	}

	// In our scan we only record transactions which state need to be checked, as`ScanTrackedTransactions`
	// is long running read transaction, it could dead lock with write transactions which we would need
	// to use to update transaction state.
	err = app.txTracker.ScanTrackedTransactions(func(tx *stakerdb.StoredTransaction) error {
		// TODO : We need to have another stare like UnstakeTransaction sent and store
		// info about transaction sent (hash) to check wheter it was confirmed after staker
		// restarts
		stakingTxHash := tx.BtcTx.TxHash()
		switch tx.State {
		case proto.TransactionState_SENT_TO_BTC:
			transactionsSentToBtc = append(transactionsSentToBtc, &stakingTxHash)
			return nil
		case proto.TransactionState_CONFIRMED_ON_BTC:
			transactionConfirmedOnBtc = append(transactionConfirmedOnBtc, &stakingTxHash)
			return nil
		// We need to check any transaction which was sent to babylon, as it could be
		// that we sent undelegation msg, but restart happened before we could update
		// database
		case proto.TransactionState_SENT_TO_BABYLON:
			// TODO: If we will have automatic unstaking, we should check wheter tx is expired
			// and proceed with sending unstake transaction
			transactionsOnBabylon = append(transactionsOnBabylon, &stakingDbInfo{
				stakingTxHash:  &stakingTxHash,
				stakingTxState: tx.State,
			})
			return nil
		case proto.TransactionState_UNBONDING_STARTED:
			transactionsOnBabylon = append(transactionsOnBabylon, &stakingDbInfo{
				stakingTxHash:  &stakingTxHash,
				stakingTxState: tx.State,
			})
			return nil
		case proto.TransactionState_UNBONDING_SIGNATURES_RECEIVED:
			transactionsOnBabylon = append(transactionsOnBabylon, &stakingDbInfo{
				stakingTxHash:  &stakingTxHash,
				stakingTxState: tx.State,
			})
			return nil
		case proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC:
			// unbonding tx was send to babylon, received all signatures and was confirmed on btc, nothing to do here
			return nil
		case proto.TransactionState_SPENT_ON_BTC:
			// nothing to do, staking transaction is already spent
			return nil
		default:
			return fmt.Errorf("unknown transaction state: %d", tx.State)
		}
	}, reset)

	if err != nil {
		return err
	}

	for _, txHash := range transactionsSentToBtc {
		stakingTxHash := txHash
		tx, _ := app.mustGetTransactionAndStakerAddress(stakingTxHash)
		details, status, err := app.wc.TxDetails(stakingTxHash, tx.BtcTx.TxOut[tx.StakingOutputIndex].PkScript)

		if err != nil {
			// we got some communication err, return error and kill app startup
			return err
		}

		err = app.handleBtcTxInfo(stakingTxHash, tx, stakingParams, app.currentBestBlockHeight.Load(), status, details)

		if err != nil {
			return err
		}
	}

	for _, txHash := range transactionConfirmedOnBtc {
		stakingTxHash := txHash
		alreadyOnBabylon, err := app.babylonClient.IsTxAlreadyPartOfDelegation(stakingTxHash)

		if err != nil {
			return err
		}

		if alreadyOnBabylon {
			app.logger.WithFields(logrus.Fields{
				"btcTxHash": stakingTxHash,
			}).Debug("Already confirmed transaction found on Babylon as part of delegation. Fix db state")

			// transaction is already on babylon, treat it as succesful delegation.
			app.sendDelegationResponseChan <- &sendDelegationResponse{
				txHash: stakingTxHash,
				err:    nil,
			}
		} else {
			// transaction which is not on babylon, is already confirmed on btc chain
			// get all necessary info and send it to babylon

			tx, _ := app.mustGetTransactionAndStakerAddress(stakingTxHash)
			details, status, err := app.wc.TxDetails(stakingTxHash, tx.BtcTx.TxOut[tx.StakingOutputIndex].PkScript)

			if err != nil {
				// we got some communication err, return error and kill app startup
				return err
			}

			if status != walletcontroller.TxInChain {
				// we have confirmed transaction which is not in chain. Most probably btc node
				// we are connected to lost data
				app.logger.WithFields(logrus.Fields{
					"btcTxHash": stakingTxHash,
				}).Error("Already confirmed transaction not found on btc chain.")
				return nil
			}

			app.logger.WithFields(logrus.Fields{
				"btcTxHash":                    stakingTxHash,
				"btcTxConfirmationBlockHeight": details.BlockHeight,
			}).Debug("Already confirmed transaction not sent to babylon yet. Initiate sending")

			req := &sendDelegationRequest{
				txHash:                      *stakingTxHash,
				txIndex:                     details.TxIndex,
				inlusionBlock:               details.Block,
				requiredInclusionBlockDepth: uint64(stakingParams.ConfirmationTimeBlocks),
			}

			app.sendDelegationWithTxToBabylon(req)

			return nil
		}
	}

	for _, localInfo := range transactionsOnBabylon {
		// we only can have three local states here
		if localInfo.stakingTxState == proto.TransactionState_UNBONDING_SIGNATURES_RECEIVED {
			app.logger.WithFields(logrus.Fields{
				"stakingTxHash": localInfo.stakingTxHash,
				"stakingState":  localInfo.stakingTxState,
			}).Debug("Restarting unbonding process for staking request which already received all necessary signatures")

			// we got everything we wanted from babylon, and we also tracked that unbonding transaction received
			// all required signatures. Check btc chain and based on that resume unbonding process.
			ud, err := app.txTracker.GetUnbondingTxData(localInfo.stakingTxHash)

			if err != nil {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": localInfo.stakingTxHash,
					"stakingState":  localInfo.stakingTxState,
				}).Fatalf("Failed to get unbonding data for tx wit unbonding state")
			}

			stored, address := app.mustGetTransactionAndStakerAddress(localInfo.stakingTxHash)

			unbondingTxHash := ud.UnbondingTx.TxHash()

			details, status, err := app.wc.TxDetails(&unbondingTxHash, ud.UnbondingTx.TxOut[0].PkScript)

			if err != nil {
				// some communication error, return error and kill app startup
				return fmt.Errorf("failed to get unbonding btc transaction details: %w", err)
			}

			if status == walletcontroller.TxNotFound {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": localInfo.stakingTxHash,
					"stakingState":  localInfo.stakingTxState,
				}).Debug("Unbonding transaction not found on btc chain. Sending it again")

				app.wg.Add(1)
				go app.sendUnbondingTxToBtcAndWaitForConfirmation(
					localInfo.stakingTxHash,
					address,
					stored,
					ud,
				)
			} else {
				var txHeightHint uint32

				// At this point tx is either in mempool or in chain.
				// If it is in chain, we set our height hint to inclusion block heigh
				// if it is in mempool, we set our height hint to current best block height
				if status == walletcontroller.TxInChain {
					app.logger.WithFields(logrus.Fields{
						"stakingTxHash":     localInfo.stakingTxHash,
						"stakingState":      localInfo.stakingTxState,
						"unbondingTxHeight": details.BlockHeight,
					}).Debug("Unbonding transaction in btc chain. Wait for more confirmations")

					txHeightHint = details.BlockHeight
				} else {
					app.logger.WithFields(logrus.Fields{
						"stakingTxHash":     localInfo.stakingTxHash,
						"stakingState":      localInfo.stakingTxState,
						"unbondingTxHeight": details.BlockHeight,
					}).Debug("Unbonding transaction in btc mempool. Wait for more confirmations")

					txHeightHint = app.currentBestBlockHeight.Load()
				}

				// tx is either in chain or in mempool, we need to wait for confirmation,
				waitEv, err := app.notifier.RegisterConfirmationsNtfn(
					&unbondingTxHash,
					ud.UnbondingTx.TxOut[0].PkScript,
					UnbondingTxConfirmations,
					txHeightHint,
				)

				if err != nil {
					return fmt.Errorf("failed to register unbonding tx confirmation event: %w", err)
				}

				app.wg.Add(1)
				go func(ev *notifier.ConfirmationEvent, unbondingData *stakerdb.UnbondingStoreData, stakingTxHash *chainhash.Hash) {
					defer app.wg.Done()
					app.waitForUnbondingTxConfirmation(
						ev,
						unbondingData,
						stakingTxHash,
					)
				}(waitEv, ud, localInfo.stakingTxHash)
			}
		} else if localInfo.stakingTxState == proto.TransactionState_UNBONDING_STARTED {
			app.logger.WithFields(logrus.Fields{
				"stakingTxHash": localInfo.stakingTxHash,
				"stakingState":  localInfo.stakingTxState,
			}).Debug("Restarting unbonding process for staking request which was already sent to babylon")

			// we successfuly sent unbonding transaction to babylon, and it was successfuly included in the chain.
			// start polling for unbonding signatures. If signatures are already received on babylon, `checkForUnbondingTxSignatures`
			// will quickly finish and move to the next step in unbonding process
			app.wg.Add(1)
			go app.checkForUnbondingTxSignatures(localInfo.stakingTxHash)
		} else if localInfo.stakingTxState == proto.TransactionState_SENT_TO_BABYLON {

			// we need to check this case as it is possible that we send undelegation request to babylon
			// but crashed before updating our local database.

			babylonInfo, err := app.babylonClient.QueryDelegationInfo(localInfo.stakingTxHash)

			if err != nil {
				if errors.Is(err, cl.ErrDelegationNotFound) {
					// this can only mean that babylon node is not up to data, continue startup
					app.logger.WithFields(logrus.Fields{
						"stakingTxHash": localInfo.stakingTxHash,
						"stakingState":  localInfo.stakingTxState,
					}).Error("Delegation not found on babylon, but found in local db")
					continue
				}
				// some communication error, return error and kill app startup
				return err
			}

			if babylonInfo.UndelegationInfo == nil {
				// all is fine, our local state matches babylon state, move to next hash
				continue
			}

			app.logger.WithFields(logrus.Fields{
				"stakingTxHash": localInfo.stakingTxHash,
				"stakingState":  localInfo.stakingTxState,
			}).Debug("Restarting unbonding process for staking request which was already sent to babylon but not registered in local db")

			// If we are here, it means we encountered edge case where we sent undelegation successfully
			// but staker application crashed before we could update database.
			// we just need to restart our unbonding process just after we sent unbonding transaction.
			// If jury and validator signatures are on babylon, the whole process will just finish quickly.
			// TODO: Thinkg of how to test this case. It is a bit tricky as restarting would need to happen
			// precisely after sending unbonding transaction, but before write tx to db.
			confirmation := &unbondingRequestConfirm{
				stakingTxHash:              *localInfo.stakingTxHash,
				unbondingTransaction:       babylonInfo.UndelegationInfo.UnbondingTransaction,
				unbondingTransactionScript: babylonInfo.UndelegationInfo.UnbondingTransactionScript,
				successChan:                make(chan *chainhash.Hash, 1),
			}

			PushOrQuit[*unbondingRequestConfirm](
				app.sendUnbondingRequestConfirmChan,
				confirmation,
				app.quit,
			)
		} else {
			// we should not have any other state here, so kill app
			return fmt.Errorf("unexpected local transaction state: %d", localInfo.stakingTxState)
		}
	}

	return nil
}

func (app *StakerApp) waitForStakingTxConfirmation(
	txHash chainhash.Hash,
	depthOnBtcChain uint32,
	ev *notifier.ConfirmationEvent) {
	// check we are not shutting down
	select {
	case <-app.quit:
		ev.Cancel()
		return

	default:
	}

	for {
		// TODO add handling of more events like ev.NegativeConf which signals that
		// transaction have beer reorged out of the chain
		select {
		case conf := <-ev.Confirmed:
			app.confirmationEventChan <- &confirmationEvent{
				txHash:        conf.Tx.TxHash(),
				txIndex:       conf.TxIndex,
				blockDepth:    depthOnBtcChain,
				blockHash:     *conf.BlockHash,
				blockHeight:   conf.BlockHeight,
				tx:            conf.Tx,
				inlusionBlock: conf.Block,
			}
			ev.Cancel()
			return
		case u := <-ev.Updates:
			app.logger.WithFields(logrus.Fields{
				"btcTxHash": txHash,
				"confLeft":  u,
			}).Debugf("Staking transaction received confirmation")
		case <-app.quit:
			// app is quitting, cancel the event
			ev.Cancel()
			return
		}
	}
}

func (app *StakerApp) getSlashingFee(p *cl.StakingParams) btcutil.Amount {
	feeFromBabylon := p.MinSlashingTxFeeSat

	if feeFromBabylon < minSlashingFee {
		app.logger.WithFields(logrus.Fields{
			"babylonSlashingFee":  feeFromBabylon,
			"internalSlashingFee": minSlashingFee,
		}).Debug("Slashing fee received from Babylon is too small. Using internal minimum fee")
		return minSlashingFee
	}

	return feeFromBabylon
}

func buildSlashingTxAndSig(
	delegationData *externalDelegationData,
	storedTx *stakerdb.StoredTransaction,
) (*wire.MsgTx, *schnorr.Signature, error) {

	slashingTx, err := staking.BuildSlashingTxFromStakingTx(
		storedTx.BtcTx,
		storedTx.StakingOutputIndex,
		delegationData.slashingAddress,
		int64(delegationData.slashingFee),
	)

	if err != nil {
		return nil, nil, fmt.Errorf("buidling slashing transaction failed: %w", err)
	}

	slashingTxSignature, err := staking.SignTxWithOneScriptSpendInputFromScript(
		slashingTx,
		storedTx.BtcTx.TxOut[storedTx.StakingOutputIndex],
		delegationData.stakerPrivKey,
		storedTx.TxScript,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("signing slashing transaction failed: %w", err)
	}

	return slashingTx, slashingTxSignature, nil
}

func (app *StakerApp) buildDelegationData(
	inclusionBlock *wire.MsgBlock,
	stakingTxIdx uint32,
	storedTx *stakerdb.StoredTransaction,
	slashingTx *wire.MsgTx,
	slashingTxSignature *schnorr.Signature,
	babylonPubKey *secp256k1.PubKey) (*cl.DelegationData, error) {

	proof, err := cl.GenerateProof(inclusionBlock, stakingTxIdx)

	if err != nil {
		return nil, fmt.Errorf("genereting inclusiong proof failed: %w", err)
	}

	inclusionBlockHash := inclusionBlock.BlockHash()

	dg := cl.DelegationData{
		StakingTransaction:                   storedTx.BtcTx,
		StakingTransactionIdx:                stakingTxIdx,
		StakingTransactionScript:             storedTx.TxScript,
		StakingTransactionInclusionProof:     proof,
		StakingTransactionInclusionBlockHash: &inclusionBlockHash,
		SlashingTransaction:                  slashingTx,
		SlashingTransactionSig:               slashingTxSignature,
		BabylonPk:                            babylonPubKey,
		BabylonPop:                           storedTx.Pop,
	}

	return &dg, nil
}

// helper to retrieve transaction when we are sure it must be in the store
func (app *StakerApp) mustGetTransactionAndStakerAddress(txHash *chainhash.Hash) (*stakerdb.StoredTransaction, btcutil.Address) {
	ts, err := app.txTracker.GetTransaction(txHash)

	if err != nil {
		app.logger.Fatalf("Error getting transaction state for tx %s. Eff: %v", txHash, err)
	}

	stakerAddress, err := btcutil.DecodeAddress(ts.StakerAddress, app.network)

	if err != nil {
		app.logger.Fatalf("Error decoding staker address: %s. Err: %v", ts.StakerAddress, err)
	}

	return ts, stakerAddress
}

func (app *StakerApp) getDelegationData(stakerAddress btcutil.Address) (*externalDelegationData, error) {
	params, err := app.babylonClient.Params()

	if err != nil {
		return nil, err
	}

	err = app.wc.UnlockWallet(defaultWalletUnlockTimeout)

	if err != nil {
		return nil, err
	}

	privkey, err := app.wc.DumpPrivateKey(stakerAddress)

	if err != nil {
		return nil, err
	}

	slashingFee := app.getSlashingFee(params)

	return &externalDelegationData{
		stakerPrivKey:   privkey,
		slashingAddress: params.SlashingAddress,
		babylonPubKey:   app.babylonClient.GetPubKey(),
		slashingFee:     slashingFee,
	}, nil
}

func (app *StakerApp) scheduleSendDelegationToBabylonAfter(timeout time.Duration, req *sendDelegationRequest) {
	select {
	case <-app.quit:
		return
	case <-time.After(timeout):
	}

	app.sendDelegationWithTxToBabylon(req)
}

// isBabylonBtcLcReady checks if Babylon BTC light client is ready to receive delegation
func (app *StakerApp) isBabylonBtcLcReady(req *sendDelegationRequest) (bool, error) {
	blockHash := req.inlusionBlock.BlockHash()

	depth, err := app.babylonClient.QueryHeaderDepth(&blockHash)

	if err != nil {
		app.logger.WithFields(logrus.Fields{
			"btcTxHash":    req.txHash,
			"btcBlockHash": blockHash,
			"err":          err,
		}).Error("Error getting btc header depth on babylon btc light client")

		// If header is not known to babylon, or it is on LCFork, then most probably
		// lc is not up to date. We should retry sending delegation after some time.
		if errors.Is(err, cl.ErrHeaderNotKnownToBabylon) || errors.Is(err, cl.ErrHeaderOnBabylonLCFork) {
			app.logger.WithFields(logrus.Fields{
				"btcTxHash":    req.txHash,
				"btcBlockHash": blockHash,
				"err":          err,
			}).Debug("Babylon btc light client not ready for btc header. Scheduling request for re-delivery")

			// TODO add some retry counter to send delegation request, to avoid infinite loop.
			// After some number of retries we should probably:
			// - check the status of header on btc chain. If it still confirmed then it is problem
			// with babylon light client and we can resume retrying.
			// (Or maybe extend babylon btc LC by ourselves? Stakers taking care of health of babylon LC sounds pretty good.)
			// - if it not on btc chain, then some reorg happened and we should probably re-check status of our staking tx
			// and take appropriate actions.
			go app.scheduleSendDelegationToBabylonAfter(app.config.StakerConfig.BabylonStallingInterval, req)
			return false, nil
		}

		// got some unknown error, return it to the caller
		return false, fmt.Errorf("error while getting delegation data for tx with hash %s: %w", req.txHash.String(), err)
	}

	if depth < req.requiredInclusionBlockDepth {
		app.logger.WithFields(logrus.Fields{
			"btcTxHash":     req.txHash,
			"btcBlockHash":  blockHash,
			"depth":         depth,
			"requiredDepth": req.requiredInclusionBlockDepth,
		}).Debug("Inclusion block not deep enough on Babylon btc light client. Scheduling request for re-delivery")

		go app.scheduleSendDelegationToBabylonAfter(app.config.StakerConfig.BabylonStallingInterval, req)
		return false, nil
	}

	return true, nil
}

func (app *StakerApp) buildOwnedDelegation(
	req *sendDelegationRequest,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction,
) (*cl.DelegationData, error) {
	delegationData, err := app.getDelegationData(stakerAddress)

	if err != nil {
		return nil, err
	}

	slashingTx, slashingTxSig, err := buildSlashingTxAndSig(delegationData, storedTx)

	if err != nil {
		// This is truly unexpected, most probably programming error we have
		// valid and btc confirmed staking transacion, but for some reason we cannot
		// build delegation data using our own set of libraries
		app.logger.WithFields(logrus.Fields{
			"btcTxHash":     req.txHash,
			"stakerAddress": stakerAddress,
			"err":           err,
		}).Fatalf("Failed to build delegation data for already confirmed staking transaction")
	}

	dg, err := app.buildDelegationData(
		req.inlusionBlock,
		req.txIndex,
		storedTx,
		slashingTx,
		slashingTxSig,
		delegationData.babylonPubKey,
	)

	if err != nil {
		// This is truly unexpected, it actually means we failed to build inclusion proof
		// for tx which should already be k-deep
		app.logger.WithFields(logrus.Fields{
			"btcTxHash":     req.txHash,
			"stakerAddress": stakerAddress,
			"err":           err,
		}).Fatalf("Failed to build delegation data for already confirmed staking transaction")
	}

	return dg, nil
}

func (app *StakerApp) buildDelegation(
	req *sendDelegationRequest,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction) (*cl.DelegationData, error) {

	if storedTx.Watched {
		watchedData, err := app.txTracker.GetWatchedTransactionData(&req.txHash)

		if err != nil {
			// Fatal error as if delegation is watched, the watched data must be in database
			// and must be not malformed
			app.logger.WithFields(logrus.Fields{
				"btcTxHash":     req.txHash,
				"stakerAddress": stakerAddress,
				"err":           err,
			}).Fatalf("Failed to build delegation data for already confirmed staking transaction")
		}

		dg, err := app.buildDelegationData(
			req.inlusionBlock,
			req.txIndex,
			storedTx,
			watchedData.SlashingTx,
			watchedData.SlashingTxSig,
			watchedData.StakerBabylonPubKey,
		)

		if err != nil {
			// This is truly unexpected, it actually means we failed to build inclusion proof
			// for tx which should already be k-deep
			app.logger.WithFields(logrus.Fields{
				"btcTxHash":     req.txHash,
				"stakerAddress": stakerAddress,
				"err":           err,
			}).Fatalf("Failed to build delegation data for already confirmed staking transaction")
		}

		return dg, nil
	} else {
		return app.buildOwnedDelegation(
			req,
			stakerAddress,
			storedTx,
		)
	}
}

func (app *StakerApp) handleSentToBabylon() {
	defer app.wg.Done()
	for {
		select {
		case req := <-app.sendDelegationRequestChan:
			babylonReady, err := app.isBabylonBtcLcReady(req)

			if err != nil {
				app.sendDelegationResponseChan <- &sendDelegationResponse{
					txHash: nil,
					err:    err,
				}
				continue
			}

			if !babylonReady {
				continue
			}

			storedTx, stakerAddress := app.mustGetTransactionAndStakerAddress(&req.txHash)

			app.logger.WithFields(logrus.Fields{
				"btcTxHash":     req.txHash,
				"stakerAddress": stakerAddress,
			}).Debugf("Initiating delegation to babylon")

			dg, err := app.buildDelegation(
				req,
				stakerAddress,
				storedTx,
			)

			if err != nil {
				// TODO: Most probably communication with babylon failed.
				app.logger.WithFields(logrus.Fields{
					"btcTxHash":     req.txHash,
					"stakerAddress": stakerAddress,
					"err":           err,
				}).Error("Error getting delegation data before sending delegation to babylon")

				app.sendDelegationResponseChan <- &sendDelegationResponse{
					txHash: nil,
					err:    fmt.Errorf("error while getting delegation data for tx with hash %s: %w", req.txHash.String(), err),
				}
				continue
			}

			txResp, err := app.babylonClient.Delegate(dg)

			if err != nil {
				if errors.Is(err, cl.ErrInvalidBabylonExecution) {
					// TODO: For now just kill the app to avoid construction more invalid delegations
					app.logger.WithFields(logrus.Fields{
						"btcTxHash":          req.txHash,
						"babylonTxHash":      txResp.TxHash,
						"babylonBlockHeight": txResp.Height,
						"babylonErrorCode":   txResp.Code,
						"babylonLog":         txResp.RawLog,
					}).Fatalf("Invalid delegation data sent to babylon")
				}

				// TODO: Most probably communication with babylon failed.
				app.logger.WithFields(logrus.Fields{
					"btcTxHash":     req.txHash,
					"stakerAddress": stakerAddress,
					"err":           err,
				}).Error("Error while sending delegation data to babylon")

				app.sendDelegationResponseChan <- &sendDelegationResponse{
					txHash: nil,
					err:    fmt.Errorf("error while sending delegation to babylon for btc tx with hash %s: %w", req.txHash.String(), err),
				}
				continue
			}

			// All good we have successful delegation
			app.sendDelegationResponseChan <- &sendDelegationResponse{
				txHash: &req.txHash,
			}

		case req := <-app.sendUnbondingRequestChan:
			di, err := app.babylonClient.QueryDelegationInfo(&req.stakingTxHash)

			if err != nil {
				req.errChan <- fmt.Errorf("failed to retrieve delegation info for staking tx with hash: %s : %w", req.stakingTxHash.String(), err)
				continue
			}

			if !di.Active {
				req.errChan <- fmt.Errorf("cannot sent unbonding request for staking tx with hash: %s, as delegation is not active", req.stakingTxHash.String())
				continue
			}

			if di.UndelegationInfo != nil {
				req.errChan <- fmt.Errorf("cannot sent unbonding request for staking tx with hash: %s, as unbonding request was already sent", req.stakingTxHash.String())
				continue
			}

			txResp, err := app.babylonClient.Undelegate(req.unbondingData)

			if err != nil {
				if errors.Is(err, cl.ErrInvalidBabylonExecution) {
					// Additional logging if for some reason we send unbonding request which was
					// accepted by babylon, but failed execution
					app.logger.WithFields(logrus.Fields{
						"btcTxHash":          req.stakingTxHash.String(),
						"babylonTxHash":      txResp.TxHash,
						"babylonBlockHeight": txResp.Height,
						"babylonErrorCode":   txResp.Code,
						"babylonLog":         txResp.RawLog,
					}).Error("Invalid delegation data sent to babylon")
				}

				req.errChan <- fmt.Errorf("failed to send unbonding for delegation with staking hash:%s:%w", req.stakingTxHash.String(), err)
				continue
			}

			// forward originalrequest to state updating go routine, as we need to:
			// - update staking tx state
			// - inform caller about success
			confirmation := &unbondingRequestConfirm{
				stakingTxHash:              req.stakingTxHash,
				unbondingTransaction:       req.unbondingData.UnbondingTransaction,
				unbondingTransactionScript: req.unbondingData.UnbondingTransactionScript,
				successChan:                req.successChan,
			}

			PushOrQuit[*unbondingRequestConfirm](
				app.sendUnbondingRequestConfirmChan,
				confirmation,
				app.quit,
			)

		case <-app.quit:
			return
		}
	}
}

func (app *StakerApp) sendDelegationWithTxToBabylon(
	req *sendDelegationRequest,
) {
	numOfQueuedDelegations := len(app.sendDelegationRequestChan)

	app.logger.WithFields(logrus.Fields{
		"btcTxHash": req.txHash,
		"btcTxIdx":  req.txIndex,
		"limit":     maxNumPendingDelegations,
		"lenQueue":  numOfQueuedDelegations,
	}).Debug("Queuing delegation to be send to babylon")

	app.sendDelegationRequestChan <- req
}

// TODO for now we launch this handler indefinitly. At some point we may introduce
// timeout, and if signatures are not find in this timeout, then we may submit
// evidence that validator or jury are censoring our unbonding
func (app *StakerApp) checkForUnbondingTxSignatures(stakingTxHash *chainhash.Hash) {
	checkSigTicker := time.NewTicker(app.config.StakerConfig.UnbondingTxCheckInterval)
	defer checkSigTicker.Stop()
	defer app.wg.Done()

	for {
		select {
		case <-checkSigTicker.C:
			di, err := app.babylonClient.QueryDelegationInfo(stakingTxHash)

			if err != nil {
				if errors.Is(err, cl.ErrDelegationNotFound) {
					// As we only start this handler when we are sure delegation is already on babylon
					// this can only that:
					// - either we are connected to wrong babylon network
					// - or babylon node lost data and is still syncing
					app.logger.WithFields(logrus.Fields{
						"stakingTxHash": stakingTxHash,
					}).Error("Delegation for given staking tx hash does not exsist on babylon. Check your babylon node.")
				} else {
					app.logger.WithFields(logrus.Fields{
						"stakingTxHash": stakingTxHash,
						"err":           err,
					}).Error("Error getting delegation info from babylon")
				}

				continue
			}

			if di.UndelegationInfo == nil {
				// As we only start this handler when we are sure delegation received unbonding request
				// this can only that:
				// - babylon node lost data and is still syncing, and not processed unbonding request yet
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
				}).Error("Delegation for given staking tx hash is not unbonding yet.")
				continue
			}

			if di.UndelegationInfo.JuryUnbodningSignature != nil && di.UndelegationInfo.ValidatorUnbondingSignature != nil {
				// we have both signatures, we can stop checking
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
				}).Debug("Received both required signatures for unbonding tx for staking tx with given hash")

				// first push signatures to the channel, this will block until signatures pushed on this channel
				// as channel is unbuffered
				req := &unbondingSignaturesConfirmed{
					stakingTxHash:               *stakingTxHash,
					juryUnbondingSignature:      di.UndelegationInfo.JuryUnbodningSignature,
					validatorUnbondingSignature: di.UndelegationInfo.ValidatorUnbondingSignature,
				}

				PushOrQuit[*unbondingSignaturesConfirmed](
					app.unbondingSignaturesConfirmedChan,
					req,
					app.quit,
				)

				// our job is done, we can return
				return
			}

		case <-app.quit:
			return
		}
	}
}

func (app *StakerApp) sendUnbondingTxWithWitness(
	stakingTxHash *chainhash.Hash,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction,
	unbondingData *stakerdb.UnbondingStoreData,
) error {
	if err := app.wc.UnlockWallet(defaultWalletUnlockTimeout); err != nil {
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Error("Failed to unlock btc wallet to send unbonding tx to btc")
		return err
	}

	privkey, err := app.wc.DumpPrivateKey(stakerAddress)

	if err != nil {
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Error("Failed to retrieve btc wallet private key send unbonding tx to btc")
		return err
	}

	stakerUnbondingSig, err := staking.SignTxWithOneScriptSpendInputFromScript(
		unbondingData.UnbondingTx,
		storedTx.BtcTx.TxOut[storedTx.StakingOutputIndex],
		privkey,
		storedTx.TxScript,
	)

	if err != nil {
		// Critical err we should always be able to sign unbonding tx
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Fatalf("Failed to sign unbonding tx with staker signature")
	}

	stakerWitness, err := staking.NewWitnessFromStakingScriptAndSignature(
		storedTx.TxScript,
		stakerUnbondingSig,
	)

	if err != nil {
		// Critical err we should always be able to sign unbonding tx
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Fatalf("Failed to sign unbonding tx with staker signature")
	}

	// Build valid wittness for spending staking output with all signatures
	witnessStack := wire.TxWitness(make([][]byte, 6))
	witnessStack[0] = unbondingData.UnbondingTxJurySignature.Serialize()
	witnessStack[1] = unbondingData.UnbondingTxValidatorSignature.Serialize()
	witnessStack[2] = stakerWitness[0]
	witnessStack[3] = []byte{}
	witnessStack[4] = stakerWitness[1]
	witnessStack[5] = stakerWitness[2]

	unbondingTx := unbondingData.UnbondingTx
	unbondingTx.TxIn[0].Witness = witnessStack

	_, err = app.wc.SendRawTransaction(unbondingTx, true)

	if err != nil {
		return err
	}

	return nil
}

// sendUnbondingTxToBtc sends unbonding tx to btc and registers for inclusion notification.
// It retries until it successfully sends unbonding tx to btc and registers for notification.or until program finishes
// TODO: Investigate wheter some of the errors should be treated as fatal and abort whole process
func (app *StakerApp) sendUnbondingTxToBtc(
	stakingTxHash *chainhash.Hash,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction,
	unbondingData *stakerdb.UnbondingStoreData) *notifier.ConfirmationEvent {
	for {
		err := app.sendUnbondingTxWithWitness(
			stakingTxHash,
			stakerAddress,
			storedTx,
			unbondingData,
		)

		if err == nil {
			app.logger.WithFields(logrus.Fields{
				"stakingTxHash":   stakingTxHash,
				"unbondingTxHash": unbondingData.UnbondingTx.TxHash(),
			}).Info("Unbonding transaction successfully sent to btc")
			// we can break the loop as we successfully sent unbonding tx to btc
			break
		}

		app.logger.WithFields(logrus.Fields{
			"stakingTxHash":   stakingTxHash,
			"unbondingTxHash": unbondingData.UnbondingTx.TxHash(),
			"err":             err,
		}).Error("Failed to send unbodning tx to btc. Retrying...")

		select {
		case <-time.After(unbondingSendRetryTimeout):
		case <-app.quit:
			return nil
		}
	}

	// at this moment we successfully sent unbonding tx to btc, register waiting for notification
	unbondingTxHash := unbondingData.UnbondingTx.TxHash()
	for {
		notificationEv, err := app.notifier.RegisterConfirmationsNtfn(
			&unbondingTxHash,
			unbondingData.UnbondingTx.TxOut[0].PkScript,
			UnbondingTxConfirmations,
			app.currentBestBlockHeight.Load(),
		)

		// TODO: Check when this error can happen, maybe this is critical error which
		// should not be retried
		if err == nil {
			app.logger.WithFields(logrus.Fields{
				"stakingTxHash":   stakingTxHash,
				"unbondingTxHash": unbondingData.UnbondingTx.TxHash(),
			}).Debug("Notification event for unbonding tx created")
			// we can break the loop as we successfully sent unbonding tx to btc
			return notificationEv
		}

		select {
		case <-time.After(unbondingSendRetryTimeout):
		case <-app.quit:
			return nil
		}
	}
}

func (app *StakerApp) waitForUnbondingTxConfirmation(
	waitEv *notifier.ConfirmationEvent,
	unbondingData *stakerdb.UnbondingStoreData,
	stakingTxHash *chainhash.Hash,
) {
	defer waitEv.Cancel()
	unbondingTxHash := unbondingData.UnbondingTx.TxHash()

	for {
		select {
		case conf := <-waitEv.Confirmed:
			app.logger.WithFields(logrus.Fields{
				"stakingTxHash":   stakingTxHash,
				"unbondingTxHash": unbondingTxHash,
				"blockHash":       conf.BlockHash,
				"blockHeight":     conf.BlockHeight,
			}).Debug("Unbonding tx confirmed")

			req := &unbondingConfirmedOnBtc{
				stakingTxHash: *stakingTxHash,
			}

			PushOrQuit[*unbondingConfirmedOnBtc](
				app.unbondingConfirmedOnBtcChan,
				req,
				app.quit,
			)

			return
		case u := <-waitEv.Updates:
			app.logger.WithFields(logrus.Fields{
				"unbondingTxHash": unbondingTxHash,
				"confLeft":        u,
			}).Debugf("Unbonding transaction received confirmation")
		case <-app.quit:
			return
		}
	}
}

// sendUnbondingTxToBtcAndWaitForConfirmation tries to send unbonding tx to btc and register for confirmation notification.
// it should be run in separate go routine.
func (app *StakerApp) sendUnbondingTxToBtcAndWaitForConfirmation(
	stakingTxHash *chainhash.Hash,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction,
	unbondingData *stakerdb.UnbondingStoreData) {

	defer app.wg.Done()
	// check we are not quitting before we start whole process
	select {
	case <-app.quit:
		return
	default:
	}

	waitEv := app.sendUnbondingTxToBtc(
		stakingTxHash,
		stakerAddress,
		storedTx,
		unbondingData,
	)

	if waitEv == nil {
		// this can be nil only when we are shutting down, just return it that case
		return
	}

	app.waitForUnbondingTxConfirmation(
		waitEv,
		unbondingData,
		stakingTxHash,
	)
}

// main event loop for the staker app
func (app *StakerApp) handleStaking() {
	defer app.wg.Done()

	for {
		select {
		case req := <-app.stakingRequestChan:
			txHash := req.stakingTx.TxHash()
			bestBlockHeight := app.currentBestBlockHeight.Load()

			app.logger.WithFields(logrus.Fields{
				"btcTxHash":              txHash,
				"currentBestBlockHeight": bestBlockHeight,
			}).Infof("Received new staking request")

			if req.isWatched() {
				err := app.txTracker.AddWatchedTransaction(
					req.stakingTx,
					req.stakingOutputIdx,
					req.stakingTxScript,
					BabylonPopToDbPop(req.pop),
					req.stakerAddress,
					req.watchTxData.slashingTx,
					req.watchTxData.slashingTxSig,
					req.watchTxData.stakerBabylonPubKey,
				)

				if err != nil {
					req.errChan <- err
					continue
				}

			} else {
				// in case of owend transaction we need to send it, and then add to our tracking db.
				_, err := app.wc.SendRawTransaction(req.stakingTx, true)
				if err != nil {
					req.errChan <- err
					continue
				}

				err = app.txTracker.AddTransaction(
					req.stakingTx,
					req.stakingOutputIdx,
					req.stakingTxScript,
					BabylonPopToDbPop(req.pop),
					req.stakerAddress,
				)

				if err != nil {
					req.errChan <- err
					continue
				}
			}

			if err := app.waitForStakingTransactionConfirmation(
				&txHash,
				req.stakingOutputPkScript,
				req.requiredDepthOnBtcChain,
				uint32(bestBlockHeight),
			); err != nil {
				req.errChan <- err
				continue
			}

			app.logger.WithFields(logrus.Fields{
				"btcTxHash": &txHash,
				"confLeft":  req.requiredDepthOnBtcChain,
				"watched":   req.isWatched(),
			}).Infof("Staking transaction successfully registred")

			req.successChan <- &txHash

		case confEvent := <-app.confirmationEventChan:
			if err := app.txTracker.SetTxConfirmed(&confEvent.txHash); err != nil {
				// TODO: handle this error somehow, it means we received confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", confEvent.txHash, err)
			}

			app.logger.WithFields(logrus.Fields{
				"btcTxHash":   confEvent.txHash,
				"blockHash":   confEvent.blockHash,
				"blockHeight": confEvent.blockHeight,
			}).Infof("BTC transaction has been confirmed")

			req := &sendDelegationRequest{
				txHash:                      confEvent.txHash,
				txIndex:                     confEvent.txIndex,
				inlusionBlock:               confEvent.inlusionBlock,
				requiredInclusionBlockDepth: uint64(confEvent.blockDepth),
			}

			app.sendDelegationWithTxToBabylon(req)

		case sendToBabylonConf := <-app.sendDelegationResponseChan:
			if sendToBabylonConf.err != nil {
				// TODO: For now we just kill the app, in case comms with babylon failed.
				// Ultimately we probably should:
				// 1. Add additional state in db - failedToSendToBabylon. So that after app restart
				// we can retry sending delegation which were failed
				// 2. Have some retry counter in sendToBabylonRequest which counts how many times
				// each request was already retried
				// 3. If some request was retried too many times we can:
				// a. kill the app - maybe there is no point in continuing if we cannot communicate with babylon
				// b. have some recovery mode - which diallow sending new delegations, and occasionaly
				// retry sending oldes failed delegations
				app.logger.WithFields(logrus.Fields{
					"err": sendToBabylonConf.err,
				}).Fatalf("Error sending delegation to babylon")
			}

			if err := app.txTracker.SetTxSentToBabylon(sendToBabylonConf.txHash); err != nil {
				// TODO: handle this error somehow, it means we received confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", sendToBabylonConf.txHash, err)
			}

			app.logger.WithFields(logrus.Fields{
				"btcTxHash": sendToBabylonConf.txHash,
			}).Infof("BTC transaction successfully sent to babylon as part of delegation")

		case spendTxConf := <-app.spendTxConfirmationChan:
			if err := app.txTracker.SetTxSpentOnBtc(&spendTxConf.stakingTxHash); err != nil {
				// TODO: handle this error somehow, it means we received spend stake confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", spendTxConf.stakingTxHash, err)
			}

			app.logger.WithFields(logrus.Fields{
				"btcTxHash": spendTxConf.stakingTxHash,
			}).Infof("BTC Staking transaction successfully spent and confirmed on BTC network")

		case confirmation := <-app.sendUnbondingRequestConfirmChan:
			if err := app.txTracker.SetTxUnbondingStarted(
				&confirmation.stakingTxHash,
				confirmation.unbondingTransaction,
				confirmation.unbondingTransactionScript,
			); err != nil {
				// TODO: handle this error somehow, it means we possilbly make invalid state transition
				app.logger.Fatalf("Error setting state for tx %s: %s", &confirmation.stakingTxHash, err)
			}
			app.logger.WithFields(logrus.Fields{
				"btcTxHash": confirmation.stakingTxHash,
			}).Debug("Unbonding request successfully sent to babylon, waiting for signatures")

			// start checking for signatures
			app.wg.Add(1)
			go app.checkForUnbondingTxSignatures(&confirmation.stakingTxHash)

			unbondingTxHash := confirmation.unbondingTransaction.TxHash()
			// return registered unbonding tx hash to caller
			confirmation.successChan <- &unbondingTxHash

		case unbondingSignaturesConf := <-app.unbondingSignaturesConfirmedChan:
			if err := app.txTracker.SetTxUnbondingSignaturesReceived(
				&unbondingSignaturesConf.stakingTxHash,
				unbondingSignaturesConf.validatorUnbondingSignature,
				unbondingSignaturesConf.juryUnbondingSignature,
			); err != nil {
				// TODO: handle this error somehow, it means we possilbly make invalid state transition
				app.logger.Fatalf("Error setting state for tx %s: %s", &unbondingSignaturesConf.stakingTxHash, err)
			}

			storedTx, stakerAddress := app.mustGetTransactionAndStakerAddress(&unbondingSignaturesConf.stakingTxHash)

			unbondingData, err := app.txTracker.GetUnbondingTxData(&unbondingSignaturesConf.stakingTxHash)

			if err != nil {
				app.logger.Fatalf("Error retieving unbonding data for tx %s: %s", &unbondingSignaturesConf.stakingTxHash, err)
			}

			app.logger.WithFields(logrus.Fields{
				"stakingTxHash": &unbondingSignaturesConf.stakingTxHash,
			}).Debug("Initiate sending btc unbonding tx to btc network and waiting for confirmation")

			app.wg.Add(1)
			go app.sendUnbondingTxToBtcAndWaitForConfirmation(
				&unbondingSignaturesConf.stakingTxHash,
				stakerAddress,
				storedTx,
				unbondingData,
			)

		case confOnBtc := <-app.unbondingConfirmedOnBtcChan:
			if err := app.txTracker.SetTxUnbondingConfirmedOnBtc(&confOnBtc.stakingTxHash); err != nil {
				// TODO: handle this error somehow, it means we received spend stake confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", confOnBtc.stakingTxHash, err)
			}

		case <-app.quit:
			return
		}
	}
}

func (app *StakerApp) Wallet() walletcontroller.WalletController {
	return app.wc
}

func (app *StakerApp) BabylonController() cl.BabylonClient {
	return app.babylonClient
}

// Generate proof of possessions for staker address.
// Requires btc wallet to be unlocked!
func (app *StakerApp) generatePop(stakerPrivKey *btcec.PrivateKey) (*cl.BabylonPop, error) {
	// build proof of possession, no point moving forward if staker does not have all
	// the necessary keys
	stakerKey := stakerPrivKey.PubKey()

	encodedPubKey := schnorr.SerializePubKey(stakerKey)

	babylonSig, err := app.babylonClient.Sign(
		encodedPubKey,
	)

	if err != nil {
		return nil, err
	}

	babylonSigHash := tmhash.Sum(babylonSig)

	btcSig, err := schnorr.Sign(stakerPrivKey, babylonSigHash)

	if err != nil {
		return nil, err
	}

	pop, err := cl.NewBabylonPop(
		cl.SchnorrType,
		babylonSig,
		btcSig.Serialize(),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to generate pop: %w", err)
	}

	return pop, nil
}

func (app *StakerApp) validatorExists(validatorPk *btcec.PublicKey) error {
	_, err := app.babylonClient.QueryValidator(validatorPk)

	if err != nil {
		return fmt.Errorf("error checking if validator exists on babylon chain: %w", err)
	}

	return nil
}

func GetMinStakingTime(p *cl.StakingParams) uint32 {
	// Actual minimum staking time in babylon is k+w, but setting it to that would
	// result in delegation which have voting power for 0 btc blocks.
	// therefore setting it to 2*w + k, will result in delegation with voting power
	// for at least w blocks. Therefore this conditions enforces min staking time i.e time
	// when stake is active of w blocks
	return 2*p.FinalizationTimeoutBlocks + p.ConfirmationTimeBlocks
}

func (app *StakerApp) WatchStaking(
	stakingTx *wire.MsgTx,
	stakingscript []byte,
	slashingTx *wire.MsgTx,
	slashingTxSig *schnorr.Signature,
	stakerBabylonPk *secp256k1.PubKey,
	stakerAddress btcutil.Address,
	pop *cl.BabylonPop,
) (*chainhash.Hash, error) {
	// 1. Check script matches transaction
	stakingOutputIdx, err := staking.GetIdxOutputCommitingToScript(
		stakingTx,
		stakingscript,
		app.network,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx due to script not matchin script: %w", err)
	}

	currentParams, err := app.babylonClient.Params()

	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Failed to get params: %w", err)
	}

	// 2. Check wheter slashing tx match staking tx
	scriptData, err := staking.CheckTransactions(
		slashingTx,
		stakingTx,
		int64(currentParams.MinSlashingTxFeeSat),
		currentParams.SlashingAddress,
		stakingscript,
		app.network,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid transactions: %w", err)
	}

	// 3.Check jury key in script
	if !bytes.Equal(
		schnorr.SerializePubKey(scriptData.StakingScriptData.JuryKey),
		schnorr.SerializePubKey(&currentParams.JuryPk),
	) {
		return nil, fmt.Errorf("failed to watch staking tx. Script jury key do not match current node params")
	}

	// 4.Check validator exsits
	if err := app.validatorExists(scriptData.StakingScriptData.ValidatorKey); err != nil {
		return nil, err
	}

	// 5. Check slashig tx sig is good. It implicitly verify staker pubkey, as script
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
		return nil, fmt.Errorf("failed to watch staking tx. Invalid slashing tx sig: %w", err)
	}

	// 6. Validate pop
	if err = pop.ValidatePop(stakerBabylonPk, scriptData.StakingScriptData.StakerKey, app.network); err != nil {
		return nil, fmt.Errorf("failed to watch staking tx. Invalid pop: %w", err)
	}

	app.logger.WithFields(logrus.Fields{
		"stakerAddress": stakerAddress,
		"stakingAmount": stakingTx.TxOut[stakingOutputIdx].Value,
		"btxTxHash":     stakingTx.TxHash(),
	}).Info("Received valid staking tx to watch")

	req := newWatchedStakingRequest(
		stakerAddress,
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

	app.stakingRequestChan <- req

	select {
	case reqErr := <-req.errChan:
		app.logger.WithFields(logrus.Fields{
			"stakerAddress": stakerAddress,
			"err":           reqErr,
		}).Debugf("Sending staking tx failed")

		return nil, reqErr
	case hash := <-req.successChan:
		return hash, nil
	case <-app.quit:
		return nil, nil
	}
}

func (app *StakerApp) StakeFunds(
	stakerAddress btcutil.Address,
	stakingAmount btcutil.Amount,
	validatorPk *btcec.PublicKey,
	stakingTimeBlocks uint16,
) (*chainhash.Hash, error) {

	// check we are not shutting down
	select {
	case <-app.quit:
		return nil, nil

	default:
	}

	if err := app.validatorExists(validatorPk); err != nil {
		return nil, err
	}

	params, err := app.babylonClient.Params()

	if err != nil {
		return nil, err
	}

	slashingFee := app.getSlashingFee(params)

	if stakingAmount <= slashingFee {
		return nil, fmt.Errorf("staking amount %d is less than minimum slashing fee %d",
			stakingAmount, slashingFee)
	}

	minStakingTime := GetMinStakingTime(params)
	if uint32(stakingTimeBlocks) < minStakingTime {
		return nil, fmt.Errorf("staking time %d is less than minimum staking time %d",
			stakingTimeBlocks, minStakingTime)
	}

	// unlock wallet for the rest of the operations
	// TODO consider unlock/lock with defer
	err = app.wc.UnlockWallet(defaultWalletUnlockTimeout)

	if err != nil {
		return nil, err
	}

	// build proof of possesion, no point moving forward if staker do not have all
	// the necessary keys
	stakerPrivKey, err := app.wc.DumpPrivateKey(stakerAddress)

	if err != nil {
		return nil, err
	}

	// We build pop ourselves so no need to verify it
	pop, err := app.generatePop(stakerPrivKey)

	if err != nil {
		return nil, err
	}

	output, script, err := staking.BuildStakingOutput(
		stakerPrivKey.PubKey(),
		validatorPk,
		&params.JuryPk,
		stakingTimeBlocks,
		stakingAmount,
		app.network,
	)

	if err != nil {
		return nil, err
	}

	feeRate := app.feeEstimator.EstimateFeePerKb()

	tx, err := app.wc.CreateAndSignTx([]*wire.TxOut{output}, btcutil.Amount(feeRate), stakerAddress)

	if err != nil {
		return nil, err
	}

	app.logger.WithFields(logrus.Fields{
		"stakerAddress": stakerAddress,
		"stakingAmount": output.Value,
		"btxTxHash":     tx.TxHash(),
		"fee":           feeRate,
	}).Info("Created and signed staking transaction")

	req := newOwnedStakingRequest(
		stakerAddress,
		tx,
		0,
		output.PkScript,
		script,
		params.ConfirmationTimeBlocks,
		pop,
	)

	app.stakingRequestChan <- req

	select {
	case reqErr := <-req.errChan:
		app.logger.WithFields(logrus.Fields{
			"stakerAddress": stakerAddress,
			"err":           reqErr,
		}).Debugf("Sending staking tx failed")

		return nil, reqErr
	case hash := <-req.successChan:
		return hash, nil
	case <-app.quit:
		return nil, nil
	}
}

func (app *StakerApp) GetAllDelegations() ([]*Delegation, error) {
	tracked, err := app.txTracker.GetAllStoredTransactions()

	if err != nil {
		return nil, err
	}

	var delegations []*Delegation

	for _, tx := range tracked {
		delegations = append(delegations, &Delegation{
			StakingTxHash: tx.BtcTx.TxHash().String(),
			State:         tx.State,
		})
	}

	return delegations, nil
}

func (app *StakerApp) StoredTransactions(limit, offset uint64) (*stakerdb.StoredTransactionQueryResult, error) {
	query := stakerdb.StoredTransactionQuery{
		IndexOffset:        offset,
		NumMaxTransactions: limit,
		Reversed:           false,
	}
	resp, err := app.txTracker.QueryStoredTransactions(query)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

func (app *StakerApp) GetStoredTransaction(txHash *chainhash.Hash) (*stakerdb.StoredTransaction, error) {
	return app.txTracker.GetTransaction(txHash)
}

func (app *StakerApp) ListUnspentOutputs() ([]walletcontroller.Utxo, error) {
	return app.wc.ListOutputs(false)
}

func (app *StakerApp) spendStakeTx(
	destAddress btcutil.Address,
	fundingTx *wire.MsgTx,
	fundingTxHash *chainhash.Hash,
	fundingTxStakingScript []byte,
	fundingTxStakingOutputIdx uint32,
) (*wire.MsgTx, *btcutil.Amount, error) {
	destAddressScript, err := txscript.PayToAddrScript(destAddress)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Cannot built destination script: %w", err)
	}

	script, err := staking.ParseStakingTransactionScript(fundingTxStakingScript)

	if err != nil {
		app.logger.WithFields(logrus.Fields{
			"err": err,
		}).Fatal("error parsing staking transaction script from db")
	}

	stakingOutput := fundingTx.TxOut[fundingTxStakingOutputIdx]
	newOutput := wire.NewTxOut(stakingOutput.Value, destAddressScript)

	stakingOutputOutpoint := wire.NewOutPoint(fundingTxHash, fundingTxStakingOutputIdx)
	stakingOutputAsInput := wire.NewTxIn(stakingOutputOutpoint, nil, nil)
	// need to set valid sequence to unlock tx.
	stakingOutputAsInput.Sequence = uint32(script.StakingTime)

	spendTx := wire.NewMsgTx(2)
	spendTx.AddTxIn(stakingOutputAsInput)
	spendTx.AddTxOut(newOutput)

	feeRate := app.feeEstimator.EstimateFeePerKb()

	// transaction have 1 P2TR input and does not have any change
	txSize := txsizes.EstimateVirtualSize(0, 1, 0, 0, []*wire.TxOut{newOutput}, 0)

	fee := txrules.FeeForSerializeSize(btcutil.Amount(feeRate), txSize)

	spendTx.TxOut[0].Value = spendTx.TxOut[0].Value - int64(fee)

	return spendTx, &fee, nil
}

func (app *StakerApp) waitForSpendConfirmation(stakingTxHash chainhash.Hash, ev *notifier.ConfirmationEvent) {
	// check we are not shutting down
	select {
	case <-app.quit:
		ev.Cancel()
		return

	default:
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutWaitingForSpendConfirmation)
	defer cancel()
	for {
		select {
		case <-ev.Confirmed:
			// transaction which spends staking transaction is confirmed on BTC inform
			// main loop about it
			app.spendTxConfirmationChan <- &spendTxConfirmationEvent{
				stakingTxHash,
			}
			ev.Cancel()
			return
		case <-ctx.Done():
			// we timed out waiting for confirmation, transaction is stuck in mempool
			return

		case <-app.quit:
			// app is quitting, cancel the event
			ev.Cancel()
			return
		}
	}
}

func (app *StakerApp) buildSpendStakeTx(
	stakingTxHash *chainhash.Hash,
	storedtx *stakerdb.StoredTransaction,
	destAddress btcutil.Address,
) (*spendStakeTxInfo, error) {
	if storedtx.State == proto.TransactionState_SENT_TO_BABYLON {
		// transaction is only in sent to babylon state we try to spend staking output directly
		spendTx, calculatedFee, err := app.spendStakeTx(
			destAddress,
			storedtx.BtcTx,
			stakingTxHash,
			storedtx.TxScript,
			storedtx.StakingOutputIndex,
		)

		if err != nil {
			return nil, err
		}

		return &spendStakeTxInfo{
			spendStakeTx:        spendTx,
			fundingOutputScript: storedtx.TxScript,
			fundingOutput:       storedtx.BtcTx.TxOut[storedtx.StakingOutputIndex],
			calculatedFee:       *calculatedFee,
		}, nil
	} else if storedtx.State == proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC {
		// transaction is in unbonding confirmed on BTC state, we need to retrieve
		// unbonding transaction and try to spend unbonding output
		data, err := app.txTracker.GetUnbondingTxData(stakingTxHash)

		if err != nil {
			app.logger.WithFields(logrus.Fields{
				"err": err,
			}).Fatalf("Error retrieving unbonding data for tx which unbonding tx is confirmed on BTC")
		}

		unbondingTxHash := data.UnbondingTx.TxHash()

		spendTx, calculatedFee, err := app.spendStakeTx(
			destAddress,
			data.UnbondingTx,
			&unbondingTxHash,
			data.UnbondingTxScript,
			// unbonding tx has only one output
			0,
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

// SpendStake spends stake identified by stakingTxHash. Stake can be currently locked in
// two types of outputs:
// 1. Staking output - this is output which is created by staking transaction
// 2. Unbonding output - this is output which is created by unbonding transaction, if user requested
// unbonding of his stake.
// We find in which type of output stake is locked by checking state of staking transaction, and build
// proper spend transaction based on that state.
func (app *StakerApp) SpendStake(stakingTxHash *chainhash.Hash) (*chainhash.Hash, *btcutil.Amount, error) {
	// check we are not shutting down
	select {
	case <-app.quit:
		return nil, nil, nil

	default:
	}

	tx, err := app.txTracker.GetTransaction(stakingTxHash)

	if err != nil {
		return nil, nil, err
	}

	// we cannont spend tx which is watch only.
	// TODO. To make it possible additional endpoint is needed
	if tx.Watched {
		return nil, nil, fmt.Errorf("cannot spend staking which which is in watch only mode")
	}

	// this coud happen if we stared staker on wrong network.
	// TODO: consider storing data for different networks in different folders
	// to avoid this
	// Currently we spend funds from staking transaction to the same address. This
	// could be improved by allowing user to specify destination address, although
	// this destination address would need to control the expcted priv key to sign
	// transaction
	destAddress, err := btcutil.DecodeAddress(tx.StakerAddress, app.network)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error decoding staker address: %w", err)
	}

	spendStakeTxInfo, err := app.buildSpendStakeTx(
		stakingTxHash,
		tx,
		destAddress,
	)

	if err != nil {
		return nil, nil, err
	}

	err = app.wc.UnlockWallet(defaultWalletUnlockTimeout)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error unlocking wallet: %w", err)
	}

	privKey, err := app.wc.DumpPrivateKey(destAddress)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error getting private key: %w", err)
	}

	witness, err := staking.BuildWitnessToSpendStakingOutput(
		spendStakeTxInfo.spendStakeTx,
		spendStakeTxInfo.fundingOutput,
		spendStakeTxInfo.fundingOutputScript,
		privKey,
	)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error building witness: %w", err)
	}

	spendStakeTxInfo.spendStakeTx.TxIn[0].Witness = witness

	// We do not check if transaction is spendable i.e the staking time has passed
	// as this is validated in mempool so in of not meeting this time requirement
	// we will receive error here: `transaction's sequence locks on inputs not met`
	spendTxHash, err := app.wc.SendRawTransaction(spendStakeTxInfo.spendStakeTx, true)

	if err != nil {
		return nil, nil, fmt.Errorf("cannot spend staking output. Error sending tx: %w", err)
	}

	spendTxValue := btcutil.Amount(spendStakeTxInfo.spendStakeTx.TxOut[0].Value)

	app.logger.WithFields(logrus.Fields{
		"stakeValue":    btcutil.Amount(spendStakeTxInfo.fundingOutput.Value),
		"spendTxHash":   spendTxHash,
		"spendTxValue":  spendTxValue,
		"fee":           spendStakeTxInfo.calculatedFee,
		"stakerAddress": destAddress,
		"destAddress":   destAddress,
	}).Infof("Successfully sent transaction spending staking output")

	confEvent, err := app.notifier.RegisterConfirmationsNtfn(
		spendTxHash,
		spendStakeTxInfo.spendStakeTx.TxOut[0].PkScript,
		SpendStakeTxConfirmations,
		app.currentBestBlockHeight.Load(),
	)

	if err != nil {
		return nil, nil, fmt.Errorf("spend tx sent. Error registering confirmation notifcation: %w", err)
	}

	// We are gonna mark our staking transaction as spent on BTC network, only when
	// we receive enough confirmations on btc network. This means that btc staker can send another
	// tx which will spend this staking output concurrently. In that case the first one
	// confirmed on btc networks which will mark our staking transaction as spent on BTC network.
	// TODO: we can reconsider this approach in the future.
	go app.waitForSpendConfirmation(*stakingTxHash, confEvent)

	return spendTxHash, &spendTxValue, nil
}

func (app *StakerApp) ListActiveValidators(limit uint64, offset uint64) (*cl.ValidatorsClientResponse, error) {
	return app.babylonClient.QueryValidators(limit, offset)
}

func (app *StakerApp) buildUnbondingAndSlashingTxFromStakingTx(
	storedTx *stakerdb.StoredTransaction,
	stakerPrivKey *btcec.PrivateKey,
	juryPubKey *btcec.PublicKey,
	slashingAddress btcutil.Address,
	feeRatePerKb btcutil.Amount,
	finalizationTimeBlocks uint16,
	slashingFee btcutil.Amount,
) (*cl.UndelegationData, error) {
	stakingTxHash := storedTx.BtcTx.TxHash()

	stakingScriptData, err := staking.ParseStakingTransactionScript(storedTx.TxScript)

	if err != nil {
		app.logger.WithFields(logrus.Fields{
			"stakingTxHash": stakingTxHash,
			"err":           err,
		}).Fatalf("Invalid staking transaction script in db")
	}

	stakingOutpout := storedTx.BtcTx.TxOut[storedTx.StakingOutputIndex]

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
		juryPubKey,
		finalizationTimeBlocks+1,
		btcutil.Amount(unbondingOutputValue),
		app.network,
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
		slashingAddress,
		int64(slashingFee),
		unbondingScript,
		app.network,
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

	app.logger.WithFields(logrus.Fields{
		"stakingTxHash":        stakingTxHash,
		"unbondingTxHash":      unbondingTx.TxHash(),
		"unbondingTxFeeRate":   int64(feeRatePerKb),
		"unbondingTxFee":       int64(unbondingTxFee),
		"unbondingOutputValue": unbondingOutputValue,
	}).Debug("Successfully built unbonding data")

	return &cl.UndelegationData{
		UnbondingTransaction:         unbondingTx,
		UnbondingTransactionScript:   unbondingScript,
		SlashUnbondingTransaction:    slashUnbondingTx,
		SlashUnbondingTransactionSig: slashUnbondingTxSignature,
	}, nil
}

// Initiates whole unbonding process. Whole process looks like this:
// 1. Unbonding data is build based on exsitng staking transaction data
// 2. Unbonding data is sent to babylon as part of undelegete request
// 3. If request is successful, unbonding transaction is registred in db and
// staking transaction is marked as unbonded
// 4. Staker program starts watching for unbodning transactions signatures from
// jury and validator
// 5. After gathering all signatures, unbonding transaction is sent to bitcoin
// This function returns control to the caller after step 3. Later is up to the caller
// to check what is state of unbonding transaction
func (app *StakerApp) UnbondStaking(
	stakingTxHash chainhash.Hash, feeRate *btcutil.Amount) (*chainhash.Hash, error) {
	// check we are not shutting down
	select {
	case <-app.quit:
		return nil, nil

	default:
	}

	// estimate fee rate if not provided
	var unbondingTxFeeRatePerKb btcutil.Amount
	if feeRate == nil {
		unbondingTxFeeRatePerKb = btcutil.Amount(app.feeEstimator.EstimateFeePerKb())
	} else {
		unbondingTxFeeRatePerKb = *feeRate
	}

	// 1. Check staking tx is managed by staker program
	tx, err := app.txTracker.GetTransaction(&stakingTxHash)

	if err != nil {
		return nil, fmt.Errorf("cannont unbond: %w", err)
	}

	// 2. Check tx is not watched and is in valid state
	if tx.Watched {
		return nil, fmt.Errorf("cannot unbond watched transaction")
	}

	if tx.State != proto.TransactionState_SENT_TO_BABYLON {
		return nil, fmt.Errorf("cannot unbond transaction which is not sent to babylon")
	}

	// 3. Check fee rate is larger than minimum
	if unbondingTxFeeRatePerKb < MinFeePerKb {
		return nil, fmt.Errorf("minimum fee rate is %d sat/kb", MinFeePerKb)
	}

	currentParams, err := app.babylonClient.Params()

	if err != nil {
		return nil, fmt.Errorf("cannot unbond: %w", err)
	}

	err = app.wc.UnlockWallet(defaultWalletUnlockTimeout)

	if err != nil {
		return nil, fmt.Errorf("cannot unbond: btc wallet error: %w", err)
	}

	// this can happen if we started staker on wrong network
	stakerAddress, err := btcutil.DecodeAddress(tx.StakerAddress, app.network)

	if err != nil {
		return nil, fmt.Errorf("cannot unbond: failed decode staker address.: %w", err)
	}

	stakerPrivKey, err := app.wc.DumpPrivateKey(stakerAddress)

	if err != nil {
		return nil, fmt.Errorf("cannot unbond: failed to retrieve private key.: %w", err)
	}

	unbondingData, err := app.buildUnbondingAndSlashingTxFromStakingTx(
		tx,
		stakerPrivKey,
		&currentParams.JuryPk,
		currentParams.SlashingAddress,
		unbondingTxFeeRatePerKb,
		uint16(currentParams.FinalizationTimeoutBlocks),
		app.getSlashingFee(currentParams),
	)

	if err != nil {
		return nil, err
	}

	req := newUnbondingRequest(stakingTxHash, unbondingData)

	app.sendUnbondingRequestChan <- req

	select {
	case reqErr := <-req.errChan:
		app.logger.WithFields(logrus.Fields{
			"err": reqErr,
		}).Debugf("Sending unbonding request failed")

		return nil, reqErr
	case hash := <-req.successChan:
		// return unbonding tx hash to caller
		return hash, nil
	case <-app.quit:
		return nil, nil
	}
}
