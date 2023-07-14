package staker

import (
	"errors"
	"fmt"
	"sync"

	staking "github.com/babylonchain/babylon/btcstaking"
	cl "github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/proto"
	scfg "github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/babylonchain/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cometbft/cometbft/crypto/tmhash"
	secp256k1 "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	notifier "github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/sirupsen/logrus"
)

type stakingRequest struct {
	stakerAddress         btcutil.Address
	stakingTx             *wire.MsgTx
	stakingOutputIdx      uint32
	stakingOutputPkScript []byte
	stakingTxScript       []byte
	numConfirmations      uint32
	pop                   *stakerdb.ProofOfPossession
	errChan               chan error
	successChan           chan *chainhash.Hash
}

type confirmationEvent struct {
	txHash        chainhash.Hash
	txIndex       uint32
	blckHash      chainhash.Hash
	blckHeight    uint32
	tx            *wire.MsgTx
	inlusionBlock *wire.MsgBlock
}

type sendToBabylonRequest struct {
	txHash        chainhash.Hash
	txIndex       uint32
	inlusionBlock *wire.MsgBlock
}

type sendToBabylonResponse struct {
	txHash *chainhash.Hash
	err    error
}

type externalDelegationData struct {
	// stakerPrivKey needs to be retrieved from btc wallet
	stakerPrivKey *btcec.PrivateKey
	// slashingAddress need to be retrieved from babylon
	slashingAddress btcutil.Address

	// babylonPubKey need to be retrieved from babylon keyring
	babylonPubKey *secp256k1.PubKey

	slashingFee btcutil.Amount
}

type Delegation struct {
	StakingTxHash string
	State         proto.TransactionState
}

const (
	// Temporary hack to get around the fees and the fact that babylon slashing fee is 1 satoshi
	// Slashing tx is around 113 bytes (depending on output address which we need to chose), with pretty large fee of 25 sat/b
	// this gives 2825 sats fee. Let round it up to 3000 sats just to be sure.
	minSlashingFeeAdjustment = 3000

	// maximum number of delegations that can be pending(waiting to be sent to babylon)
	// at the same time
	maxNumPendingDelegations = 100
)

type StakerApp struct {
	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
	quit      chan struct{}

	babylonClient             cl.BabylonClient
	wc                        walletcontroller.WalletController
	notifier                  notifier.ChainNotifier
	feeEstimator              FeeEstimator
	network                   *chaincfg.Params
	config                    *scfg.Config
	logger                    *logrus.Logger
	txTracker                 *stakerdb.TrackedTransactionStore
	stakingRequestChan        chan *stakingRequest
	confirmationEventChan     chan *confirmationEvent
	sendToBabylonRequestChan  chan *sendToBabylonRequest
	sendToBabylonResponseChan chan *sendToBabylonResponse
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

	nodeNotifier, err := NewNodeBackend(config.BtcNodeBackendConfig, &config.ActiveNetParams)

	if err != nil {
		return nil, err
	}

	var feeEstimator FeeEstimator
	switch config.BtcNodeBackendConfig.EstimationMode {
	case scfg.StaticFeeEstimation:
		feeEstimator = NewStaticBtcFeeEstimator()
	case scfg.DynamicFeeEstimation:
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
		// request to sent to babylon
		sendToBabylonRequestChan: make(chan *sendToBabylonRequest, maxNumPendingDelegations),

		// event for when delegation is sent to babylon and included in babylon
		sendToBabylonResponseChan: make(chan *sendToBabylonResponse),
	}, nil
}

func (app *StakerApp) Start() error {
	var startErr error
	app.startOnce.Do(func() {
		app.logger.Infof("Starting StakerApp")

		// TODO: This can take a long time as it conntects to node. Maybe make it cancellable?
		// although staker without node is not very useful

		app.logger.Infof("Connecting to node backend: %s", app.config.BtcNodeBackendConfig.Nodetype)
		err := app.notifier.Start()
		if err != nil {
			startErr = err
			return
		}

		app.logger.Infof("Successfully connected to node backend: %s", app.config.BtcNodeBackendConfig.Nodetype)

		app.wg.Add(2)
		go app.handleSentToBabylon()
		go app.handleStaking()
	})

	return startErr
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

func (app *StakerApp) waitForConfirmation(txHash chainhash.Hash, ev *notifier.ConfirmationEvent) {
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
				blckHash:      *conf.BlockHash,
				blckHeight:    conf.BlockHeight,
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

func (app *StakerApp) buildDelegationData(
	delegationData *externalDelegationData,
	inclusionBlock *wire.MsgBlock,
	stakingTxIdx uint32,
	stakerAddress btcutil.Address,
	stakingTx *wire.MsgTx,
	stakingTxScript []byte,
	stakingOutputIdx uint32,
	proofOfPossession *stakerdb.ProofOfPossession,
	minSlashingFee int64) (*cl.DelegationData, error) {

	slashingTx, err := staking.BuildSlashingTxFromStakingTx(
		stakingTx,
		stakingOutputIdx,
		delegationData.slashingAddress,
		// use minimum slashing fee
		// TODO: consider dust rules and the fact that staking amount must cover two fees i.e
		// staking tx fee and slashing tx fee
		int64(minSlashingFee),
	)

	if err != nil {
		return nil, fmt.Errorf("buidling slashing transaction failed: %w", err)
	}

	signature, err := staking.SignTxWithOneScriptSpendInputFromScript(
		slashingTx,
		stakingTx.TxOut[stakingOutputIdx],
		delegationData.stakerPrivKey,
		stakingTxScript,
	)

	if err != nil {
		return nil, fmt.Errorf("signing slashing transaction failed: %w", err)
	}

	proof, err := cl.GenerateProof(inclusionBlock, stakingTxIdx)

	if err != nil {
		return nil, fmt.Errorf("genereting inclusiong proof failed: %w", err)
	}

	dg := cl.DelegationData{
		StakingTransaction:               stakingTx,
		StakingTransactionIdx:            stakingTxIdx,
		StakingTransactionScript:         stakingTxScript,
		StakingTransactionInclusionProof: proof,
		SlashingTransaction:              slashingTx,
		SlashingTransactionSig:           signature,
		BabylonPk:                        delegationData.babylonPubKey,
		BabylonEcdsaSigOverBtcPk:         proofOfPossession.BabylonSigOverBtcPk,
		BtcSchnorrSigOverBabylonSig:      proofOfPossession.BtcSchnorrSigOverBabylonSig,
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

	err = app.wc.UnlockWallet(15)

	if err != nil {
		return nil, err
	}

	privkey, err := app.wc.DumpPrivateKey(stakerAddress)

	if err != nil {
		return nil, err
	}

	return &externalDelegationData{
		stakerPrivKey:   privkey,
		slashingAddress: params.SlashingAddress,
		babylonPubKey:   app.babylonClient.GetPubKey(),
		slashingFee:     params.MinSlashingTxFeeSat,
	}, nil
}

func (app *StakerApp) handleSentToBabylon() {
	defer app.wg.Done()
	for {
		select {
		case req := <-app.sendToBabylonRequestChan:
			storedTx, stakerAddress := app.mustGetTransactionAndStakerAddress(&req.txHash)

			app.logger.WithFields(logrus.Fields{
				"btcTxHash":     req.txHash,
				"stakerAddress": stakerAddress,
			}).Debugf("Initiating delegation to babylon")

			delegationData, err := app.getDelegationData(stakerAddress)

			if err != nil {
				// TODO: Most probably communication with babylon failed.
				app.logger.WithFields(logrus.Fields{
					"btcTxHash":     req.txHash,
					"stakerAddress": stakerAddress,
					"err":           err,
				}).Error("Error getting delegation data before sending delegation to babylon")

				app.sendToBabylonResponseChan <- &sendToBabylonResponse{
					txHash: nil,
					err:    fmt.Errorf("error while getting delegation data for tx with hash %s: %w", req.txHash.String(), err),
				}
				continue
			}

			dg, err := app.buildDelegationData(
				delegationData,
				req.inlusionBlock,
				req.txIndex,
				stakerAddress,
				storedTx.BtcTx,
				storedTx.TxScript,
				storedTx.StakingOutputIndex,
				storedTx.Pop,
				int64(delegationData.slashingFee)+minSlashingFeeAdjustment,
			)

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

			txResp, err := app.babylonClient.Delegate(dg)

			if err != nil {
				if errors.Is(err, cl.ErrInvalidBabylonDelegation) {
					// TODO: For not just kill the app to avoid construction more invalid delegations
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

				app.sendToBabylonResponseChan <- &sendToBabylonResponse{
					txHash: nil,
					err:    fmt.Errorf("error while sending delegation to babylon for btc tx with hash %s: %w", req.txHash.String(), err),
				}
				continue
			}

			// All good we have successful delegation
			app.sendToBabylonResponseChan <- &sendToBabylonResponse{
				txHash: &req.txHash,
			}

		case <-app.quit:
			return
		}
	}
}

func (app *StakerApp) sendDelegationWithTxToBabylon(
	txHash chainhash.Hash,
	txIndex uint32,
	inlusionBlock *wire.MsgBlock,
) {

	req := &sendToBabylonRequest{
		txHash:        txHash,
		txIndex:       txIndex,
		inlusionBlock: inlusionBlock,
	}

	numOfQueuedDelegations := len(app.sendToBabylonRequestChan)

	app.logger.WithFields(logrus.Fields{
		"btcTxHash": txHash,
		"btcTxIdx":  txIndex,
		"limit":     maxNumPendingDelegations,
		"lenQueue":  numOfQueuedDelegations,
	}).Debug("Queuing delegation to be send to babylon")

	app.sendToBabylonRequestChan <- req
}

// main event loop for the staker app
func (app *StakerApp) handleStaking() {
	defer app.wg.Done()

	for {
		select {
		case req := <-app.stakingRequestChan:
			txHash := req.stakingTx.TxHash()
			bestBlockHeight, err := app.wc.BestBlockHeight()

			if err != nil {
				req.errChan <- err
				continue
			}

			app.logger.WithFields(logrus.Fields{
				"btcTxHash":              txHash,
				"currentBestBlockHeight": bestBlockHeight,
			}).Infof("Received new staking request")

			hash, err := app.wc.SendRawTransaction(req.stakingTx, true)
			if err != nil {
				req.errChan <- err
				continue
			}

			err = app.txTracker.AddTransaction(
				req.stakingTx,
				req.stakingOutputIdx,
				req.stakingTxScript,
				req.pop,
				req.stakerAddress,
			)

			if err != nil {
				req.errChan <- err
				continue
			}

			confEvent, err := app.notifier.RegisterConfirmationsNtfn(
				hash,
				// TODO: staking script is necessary here, to support light clients. Maybe we could
				// suppport neutrino backends, so stakers could use spv wallets.
				req.stakingOutputPkScript,
				req.numConfirmations,
				uint32(bestBlockHeight),
				// notication must include block that mined the tx, this is necessary to build
				// inclusion proof
				notifier.WithIncludeBlock(),
			)

			if err != nil {
				req.errChan <- err
				continue
			}
			// TODO: add some wait group here, to wait for all go routines to finish
			// before returning from this function
			go app.waitForConfirmation(txHash, confEvent)

			app.logger.WithFields(logrus.Fields{
				"btcTxHash": hash,
				"confLeft":  req.numConfirmations,
			}).Infof("Staking transaction successfully sent to BTC network. Waiting for confirmations")

			req.successChan <- hash

		case confEvent := <-app.confirmationEventChan:
			err := app.txTracker.SetTxConfirmed(&confEvent.txHash)

			if err != nil {
				// TODO: handle this error somehow, it means we received confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", confEvent.txHash, err)
			}

			app.logger.WithFields(logrus.Fields{
				"btcTxHash":  confEvent.txHash,
				"blockHash":  confEvent.blckHash,
				"blckHeight": confEvent.blckHeight,
			}).Infof("BTC transaction has been confirmed")

			app.sendDelegationWithTxToBabylon(
				confEvent.txHash,
				confEvent.txIndex,
				confEvent.inlusionBlock,
			)

		case sentToBabylonConf := <-app.sendToBabylonResponseChan:
			if sentToBabylonConf.err != nil {
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
					"err": sentToBabylonConf.err,
				}).Fatalf("Error sending delegation to babylon")
			}

			err := app.txTracker.SetTxSentToBabylon(sentToBabylonConf.txHash)

			if err != nil {
				// TODO: handle this error somehow, it means we received confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", sentToBabylonConf.txHash, err)
			}

			app.logger.WithFields(logrus.Fields{
				"btcTxHash": sentToBabylonConf.txHash,
			}).Infof("BTC transaction successfully sent to babylon as part of delegation")

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

// Generate proof of possesions for staker address.
// Requieres btc wallet to unlocked!
func (app *StakerApp) generatePop(stakerPrivKey *btcec.PrivateKey) (*stakerdb.ProofOfPossession, error) {
	// build proof of possesion, no point moving forward if staker do not have all
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

	pop := stakerdb.NewProofOfPossession(
		babylonSig,
		btcSig.Serialize(),
	)

	return pop, nil
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

	params, err := app.babylonClient.Params()

	if err != nil {
		return nil, err
	}

	// TODO: consider dust rules and the fact that staking amount must cover two fees.
	// TODO: Adding 1000 satoshis to cover fees for now as babylon return 1sat currently
	var minSlashingFee = params.MinSlashingTxFeeSat + minSlashingFeeAdjustment

	if stakingAmount <= minSlashingFee {
		return nil, fmt.Errorf("staking amount %d is less than minimum slashing fee %d",
			stakingAmount, params.MinSlashingTxFeeSat)
	}

	if uint32(stakingTimeBlocks) < params.FinalizationTimeoutBlocks {
		return nil, fmt.Errorf("staking time %d is less than minimum finalization time %d",
			stakingTimeBlocks, params.FinalizationTimeoutBlocks)
	}

	// unlock wallet for the rest of the operations
	// TODO consider unlock/lock with defer
	err = app.wc.UnlockWallet(15)

	if err != nil {
		return nil, err
	}

	// build proof of possesion, no point moving forward if staker do not have all
	// the necessary keys
	stakerPrivKey, err := app.wc.DumpPrivateKey(stakerAddress)

	if err != nil {
		return nil, err
	}

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

	req := &stakingRequest{
		stakerAddress:         stakerAddress,
		stakingTx:             tx,
		stakingOutputIdx:      0,
		stakingOutputPkScript: output.PkScript,
		stakingTxScript:       script,
		// adding plus 1, as most libs in bitcoind world count best block as being 1 confirmation, but in
		// babylon numenclature it is 0 deep
		numConfirmations: params.ComfirmationTimeBlocks + 1,
		pop:              pop,
		errChan:          make(chan error),
		successChan:      make(chan *chainhash.Hash),
	}

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

func (app *StakerApp) GetStoredTransaction(txHash *chainhash.Hash) (*stakerdb.StoredTransaction, error) {
	return app.txTracker.GetTransaction(txHash)
}
