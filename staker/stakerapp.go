package staker

import (
	"fmt"
	"sync"

	staking "github.com/babylonchain/babylon/btcstaking"
	cl "github.com/babylonchain/btc-staker/babylonclient"
	scfg "github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	notifier "github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/sirupsen/logrus"
)

type stakingRequest struct {
	stakingTx             *wire.MsgTx
	stakingOutputPkScript []byte
	stakingTxScript       []byte
	numConfirmations      uint32
	errChan               chan error
	successChan           chan *chainhash.Hash
}

type confirmationEvent struct {
	txHash chainhash.Hash
}

type Delegation struct {
	StakingTxHash string
	State         TxState
}

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
	txTracker             *StakingTxTracker
	stakingRequestChan    chan *stakingRequest
	confirmationEventChan chan *confirmationEvent
}

func NewStakerAppFromConfig(
	config *scfg.Config,
	logger *logrus.Logger,
) (*StakerApp, error) {
	// TODO: If we want to support multiple wallet types, this is most probably the place to decide
	// on concrete implementation
	walletClient, err := walletcontroller.NewRpcWalletController(config)
	if err != nil {
		return nil, err
	}

	tracker := NewStakingTxTracker()

	// TODO use real client
	cl := cl.GetMockClient()

	nodeNotifier, err := NewNodeBackend(config.BtcNodeBackendConfig, &config.ActiveNetParams)

	if err != nil {
		return nil, err
	}

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

		err := app.notifier.Start()
		if err != nil {
			startErr = err
			return
		}

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
				txHash: conf.Tx.TxHash(),
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

			err = app.txTracker.Add(req.stakingTx, req.stakingTxScript)

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
			txHash := confEvent.txHash.String()
			app.logger.Debugf("Received confirmation event for tx %s", txHash)
			err := app.txTracker.SetState(txHash, Confirmed)

			if err != nil {
				// TODO: handle this error somehow, it means we received confirmation for tx which we do not store
				// which is seems like programming error. Maybe panic?
				app.logger.Errorf("Error setting state for tx %s: %s", txHash, err)
			}

			// TODO: Start go routine which handles:
			// - building slashing tx
			// - buidling inclusions proof for tx
			// - sending delegation to babylon

		case <-app.quit:
			return
		}
	}
}

func (app *StakerApp) Wallet() walletcontroller.WalletController {
	return app.wc
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

	if stakingAmount < params.MinSlashingTxFeeSat {
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

	stakerKey, err := app.wc.AddressPublicKey(stakerAddress)

	if err != nil {
		return nil, err
	}

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
		stakingTx:             tx,
		stakingOutputPkScript: output.PkScript,
		stakingTxScript:       script,
		// adding plus 1, as most libs in bitcoind world count best block as being 1 confirmation, but in
		// babylon numenclature it is 0 deep
		numConfirmations: params.ComfirmationTimeBlocks + 1,
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

func (app *StakerApp) GetAllDelegations() []*Delegation {
	tracked := app.txTracker.GetAll()

	var delegations []*Delegation

	for _, tx := range tracked {
		delegations = append(delegations, &Delegation{
			StakingTxHash: tx.tx.TxHash().String(),
			State:         tx.state,
		})
	}

	return delegations
}
