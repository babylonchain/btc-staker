package staker

import (
	"errors"
	"fmt"
	"time"

	cl "github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/sirupsen/logrus"
)

// TODO: All functions and types declared in this file should be moved to separate package
// and be part of new module which will be responsible for communication with babylon chain i.e
// retrieving data from babylon chain, sending data to babylon chain, queuing data to be send etc.

type sendDelegationRequest struct {
	txHash                      chainhash.Hash
	txIndex                     uint32
	inclusionBlock              *wire.MsgBlock
	requiredInclusionBlockDepth uint64
}

func (app *StakerApp) buildOwnedDelegation(
	req *sendDelegationRequest,
	stakerAddress btcutil.Address,
	storedTx *stakerdb.StoredTransaction,
	stakingTxInclusionProof []byte,
) (*cl.DelegationData, error) {
	delegationData, err := app.retrieveExternalDelegationData(stakerAddress, storedTx.ChangeAddress)
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
		req.inclusionBlock,
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
			req.inclusionBlock,
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

			if di.UndelegationInfo.CovenantUnbondingSignature != nil && di.UndelegationInfo.ValidatorUnbondingSignature != nil {
				// we have both signatures, we can stop checking
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
				}).Debug("Received both required signatures for unbonding tx for staking tx with given hash")

				// first push signatures to the channel, this will block until signatures pushed on this channel
				// as channel is unbuffered
				req := &unbondingTxSignaturesConfirmedOnBabylonEvent{
					stakingTxHash:               *stakingTxHash,
					covenantUnbondingSignature:  di.UndelegationInfo.CovenantUnbondingSignature,
					validatorUnbondingSignature: di.UndelegationInfo.ValidatorUnbondingSignature,
				}

				utils.PushOrQuit[*unbondingTxSignaturesConfirmedOnBabylonEvent](
					app.unbondingTxSignaturesConfirmedOnBabylonEvChan,
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
