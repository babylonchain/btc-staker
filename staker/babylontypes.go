package staker

import (
	"errors"
	"fmt"
	"time"

	cl "github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/sirupsen/logrus"
)

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

type unbondingSignaturesConfirmed struct {
	stakingTxHash               chainhash.Hash
	juryUnbondingSignature      *schnorr.Signature
	validatorUnbondingSignature *schnorr.Signature
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
	stakingTxInclusionProof []byte,
) (*cl.DelegationData, error) {
	delegationData, err := app.retrieveExternalDelegationData(stakerAddress)

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

	dg := createDelegationData(
		req.inlusionBlock,
		req.txIndex,
		storedTx,
		slashingTx,
		slashingTxSig,
		delegationData.babylonPubKey,
		stakingTxInclusionProof,
	)

	return dg, nil
}

func (app *StakerApp) buildDelegation(
	req *sendDelegationRequest,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction) (*cl.DelegationData, error) {

	stakingTxInclusionProof := app.mustBuildInclusionProof(req)

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

		dg := createDelegationData(
			req.inlusionBlock,
			req.txIndex,
			storedTx,
			watchedData.SlashingTx,
			watchedData.SlashingTxSig,
			watchedData.StakerBabylonPubKey,
			stakingTxInclusionProof,
		)
		return dg, nil
	} else {
		return app.buildOwnedDelegation(
			req,
			stakerAddress,
			storedTx,
			stakingTxInclusionProof,
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
func (app *StakerApp) checkForUnbondingTxSignaturesOnBabylon(stakingTxHash *chainhash.Hash) {
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

func (app *StakerApp) validatorExists(validatorPk *btcec.PublicKey) error {
	_, err := app.babylonClient.QueryValidator(validatorPk)

	if err != nil {
		return fmt.Errorf("error checking if validator exists on babylon chain: %w", err)
	}

	return nil
}
