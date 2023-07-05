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
	"github.com/sirupsen/logrus"
)

type stakingRequest struct {
	stakingTx       *wire.MsgTx
	stakingTxScript []byte
	errChan         chan error
	successChan     chan *chainhash.Hash
}

type StakerApp struct {
	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
	quit      chan struct{}

	babylonClient      cl.BabylonClient
	wc                 walletcontroller.WalletController
	network            *chaincfg.Params
	config             *scfg.Config
	logger             *logrus.Logger
	txTracker          *StakingTxTracker
	stakingRequestChan chan *stakingRequest
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

	return &StakerApp{
		babylonClient:      cl,
		wc:                 walletClient,
		network:            &config.ActiveNetParams,
		txTracker:          tracker,
		config:             config,
		logger:             logger,
		quit:               make(chan struct{}),
		stakingRequestChan: make(chan *stakingRequest),
	}, nil
}

func (app *StakerApp) Start() {
	app.startOnce.Do(func() {
		app.logger.Infof("Starting StakerApp")
		app.wg.Add(1)
		go app.handleStaking()
	})
}

func (app *StakerApp) Stop() {
	app.stopOnce.Do(func() {
		app.logger.Infof("Stopping StakerApp")
		close(app.quit)
		app.wg.Wait()
	})
}

// main event loop for the staker app
func (app *StakerApp) handleStaking() {
	defer app.wg.Done()

	for {
		select {
		case req := <-app.stakingRequestChan:
			txHash := req.stakingTx.TxHash().String()
			app.logger.Debugf("Received staking request for tx %s", txHash)
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

			req.successChan <- hash

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
	delegatorPk *btcec.PublicKey,
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

	if uint32(stakingTimeBlocks) < params.MinmumStakingTimeBlocks {
		return nil, fmt.Errorf("staking time %d is less than minimum staking time %d",
			stakingTimeBlocks, params.MinmumStakingTimeBlocks)
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

	ouput, script, err := staking.BuildStakingOutput(
		stakerKey,
		delegatorPk,
		&params.JuryPk,
		stakingTimeBlocks,
		stakingAmount,
		app.network,
	)

	if err != nil {
		return nil, err
	}

	tx, err := app.wc.CreateAndSignTx([]*wire.TxOut{ouput}, 100, stakerAddress)

	if err != nil {
		return nil, err
	}

	req := &stakingRequest{
		stakingTx:       tx,
		stakingTxScript: script,
		errChan:         make(chan error),
		successChan:     make(chan *chainhash.Hash),
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
