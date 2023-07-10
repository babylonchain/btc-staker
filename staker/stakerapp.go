package staker

import (
	"fmt"
	"sync"

	staking "github.com/babylonchain/babylon/btcstaking"
	cl "github.com/babylonchain/btc-staker/babylonclient"
	scfg "github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/babylonchain/btc-staker/stakerproto"
	"github.com/babylonchain/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cometbft/cometbft/crypto/tmhash"
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
	tx            *wire.MsgTx
	inlusionBlock *wire.MsgBlock
}

type Delegation struct {
	StakingTxHash string
	State         stakerproto.TransactionState
}

const (
	// Temporary hack to get around the fees and the fact that babylon slashing fee is 1 satoshi
	minSlashingFeeAdjustment = 1000
)

type StakerApp struct {
	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
	quit      chan struct{}

	babylonClient         cl.BabylonClient
	wc                    walletcontroller.WalletController
	notifier              notifier.ChainNotifier
	network               *chaincfg.Params
	config                *scfg.Config
	logger                *logrus.Logger
	txTracker             *stakerdb.TrackedTransactionStore
	stakingRequestChan    chan *stakingRequest
	confirmationEventChan chan *confirmationEvent
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

	cl, err := cl.NewBabylonController(config.BabylonConfig, &config.ActiveNetParams)

	if err != nil {
		return nil, err
	}

	nodeNotifier, err := NewNodeBackend(config.BtcNodeBackendConfig, &config.ActiveNetParams)

	if err != nil {
		return nil, err
	}

	return NewStakerAppFromDeps(
		config,
		logger,
		cl,
		walletClient,
		nodeNotifier,
		tracker,
	)
}

func NewStakerAppFromDeps(
	config *scfg.Config,
	logger *logrus.Logger,
	cl cl.BabylonClient,
	walletClient walletcontroller.WalletController,
	nodeNotifier notifier.ChainNotifier,
	tracker *stakerdb.TrackedTransactionStore,
) (*StakerApp, error) {
	return &StakerApp{
		babylonClient:         cl,
		wc:                    walletClient,
		notifier:              nodeNotifier,
		network:               &config.ActiveNetParams,
		txTracker:             tracker,
		config:                config,
		logger:                logger,
		quit:                  make(chan struct{}),
		stakingRequestChan:    make(chan *stakingRequest),
		confirmationEventChan: make(chan *confirmationEvent),
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

		app.wg.Add(1)
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

func (app *StakerApp) WaitForConfirmation(ev *notifier.ConfirmationEvent) {
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
				tx:            conf.Tx,
				inlusionBlock: conf.Block,
			}
			ev.Cancel()
			return
		case <-app.quit:
			// app is quitting, cancel the event
			ev.Cancel()
			return
		}
	}
}

func (app *StakerApp) buildDelegationData(
	inclusionBlock *wire.MsgBlock,
	stakingTxIdx uint32,
	stakerAddress btcutil.Address,
	stakingTx *wire.MsgTx,
	stakingTxScript []byte,
	stakingOutputIdx uint32,
	proofOfPossession *stakerdb.ProofOfPossession,
	minSlashingFee int64) (*cl.DelegationData, error) {

	params, err := app.babylonClient.Params()

	if err != nil {
		return nil, err
	}

	babylonPk := app.babylonClient.GetPubKey()

	err = app.wc.UnlockWallet(15)

	if err != nil {
		return nil, err
	}

	privkey, err := app.wc.DumpPrivateKey(stakerAddress)

	if err != nil {
		return nil, err
	}

	slashingTx, err := staking.BuildSlashingTxFromStakingTx(
		stakingTx,
		stakingOutputIdx,
		params.SlashingAddress,
		// use minimum slashing fee
		// TODO: consider dust rules and the fact that staking amount must cover two fees i.e
		// staking tx fee and slashing tx fee
		int64(minSlashingFee),
	)

	if err != nil {
		return nil, err
	}

	signature, err := staking.SignTxWithOneScriptSpendInputFromScript(
		slashingTx,
		stakingTx.TxOut[stakingOutputIdx],
		privkey,
		stakingTxScript,
	)

	if err != nil {
		return nil, err
	}

	proof, err := cl.GenerateProof(inclusionBlock, stakingTxIdx)

	if err != nil {
		return nil, err
	}

	dg := cl.DelegationData{
		StakingTransaction:               stakingTx,
		StakingTransactionIdx:            stakingTxIdx,
		StakingTransactionScript:         stakingTxScript,
		StakingTransactionInclusionProof: proof,
		SlashingTransaction:              slashingTx,
		SlashingTransactionsSig:          signature,
		BabylonPk:                        babylonPk,
		BabylonEcdsaSigOverBtcPk:         proofOfPossession.BabylonSigOverBtcPk,
		BtcSchnorrSigOverBabylonSig:      proofOfPossession.BtcSchnorrSigOverBabylonSig,
	}

	return &dg, nil
}

// main event loop for the staker app
func (app *StakerApp) handleStaking() {
	defer app.wg.Done()

	for {
		select {
		case req := <-app.stakingRequestChan:
			txHash := req.stakingTx.TxHash().String()
			bestBlockHeight, err := app.wc.BestBlockHeight()
			app.logger.Debugf("Received staking request for tx %s. Current best block height: %d", txHash, bestBlockHeight)

			if err != nil {
				req.errChan <- err
				continue
			}

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

			app.logger.Infof("Saved staking tx %s to db", txHash)

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
			go app.WaitForConfirmation(confEvent)

			app.logger.Debugf("Staking tx %s sent", txHash)
			req.successChan <- hash

		case confEvent := <-app.confirmationEventChan:
			app.logger.Debugf("Received confirmation event for tx %s", confEvent.txHash)

			err := app.txTracker.SetTxConfirmed(&confEvent.txHash)

			if err != nil {
				// TODO: handle this error somehow, it means we received confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", confEvent.txHash, err)
			}

			// TODO Following code should porobably be started in seprarate go routine
			// to not block main event loop
			ts, err := app.txTracker.GetTransaction(&confEvent.txHash)

			if err != nil {
				app.logger.Fatalf("Error getting transaction state for tx %s. Eff: %v", confEvent.txHash, err)
			}

			app.logger.Debugf("Staker address is: %v", ts.StakerAddress)

			stakerAddress, err := btcutil.DecodeAddress(ts.StakerAddress, app.network)

			if err != nil {
				app.logger.Fatalf("Error decoding staker address: %s. Err: %v", ts.StakerAddress, err)
			}

			dg, err := app.buildDelegationData(
				confEvent.inlusionBlock,
				confEvent.txIndex,
				stakerAddress,
				ts.BtcTx,
				ts.TxScript,
				ts.StakingOutputIndex,
				ts.Pop,
				minSlashingFeeAdjustment,
			)

			if err != nil {
				// all data here should be correct and validated, lets just kill the app
				app.logger.Fatalf("Error building delegation data: %v", err)
			}

			// TODO Handle retries
			_, err = app.babylonClient.Delegate(dg)

			if err != nil {
				app.logger.Debugf("Error sending delegation: %v", err)
				continue
			}

			err = app.txTracker.SetTxSentToBabylon(&confEvent.txHash)

			if err != nil {
				// TODO: handle this error somehow, it means we received confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Fatalf("Error setting state for tx %s: %s", confEvent.txHash, err)
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

	if stakingAmount < minSlashingFee {
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

	babylonAddress := app.babylonClient.GetKeyAddress()

	if err != nil {
		return nil, err
	}

	stakerKey := stakerPrivKey.PubKey()

	encodedPubKey := schnorr.SerializePubKey(stakerKey)

	babylonSig, _, err := app.babylonClient.Sign(
		encodedPubKey, babylonAddress,
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

	output, script, err := staking.BuildStakingOutput(
		stakerKey,
		validatorPk,
		&params.JuryPk,
		stakingTimeBlocks,
		stakingAmount,
		app.network,
	)

	if err != nil {
		return nil, err
	}

	// todo: fix fees
	tx, err := app.wc.CreateAndSignTx([]*wire.TxOut{output}, 100, stakerAddress)

	if err != nil {
		return nil, err
	}

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
