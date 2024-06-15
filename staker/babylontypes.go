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

// TODO: All functions and types declared in this file should be moved to a separate package
// and be part of new module which will be responsible for communication with babylon chain i.e
// retrieving data from babylon chain, sending data to babylon chain, queuing data to be sent etc.

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
	externalData, err := app.retrieveExternalDelegationData(stakerAddress)
	if err != nil {
		return nil, err
	}

	slashingFee := app.getSlashingFee(externalData.babylonParams.MinSlashingTxFeeSat)

	slashingTx, slashingTxSig, err := buildSlashingTxAndSig(slashingFee, externalData, storedTx, app.network)
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

	// TODO: Option to use custom fee rate, as estimator uses pretty big value for fee
	// in case of estimation failure (25 sat/byte)
	unbondingTxFeeRatePerKb := btcutil.Amount(app.feeEstimator.EstimateFeePerKb())

	undelegationData, err := createUndelegationData(
		storedTx,
		externalData.stakerPrivKey,
		externalData.babylonParams.CovenantPks,
		externalData.babylonParams.CovenantQuruomThreshold,
		externalData.babylonParams.SlashingAddress,
		unbondingTxFeeRatePerKb,
		// TODO: Possiblity to customize finalization time
		uint16(externalData.babylonParams.MinUnbondingTime)+1,
		app.getSlashingFee(externalData.babylonParams.MinSlashingTxFeeSat),
		externalData.babylonParams.SlashingRate,
		app.network,
	)

	if err != nil {
		// TODO: Most probable cause for this error would be some kind of problem with fees
		return nil, fmt.Errorf("error creating undelegation data: %w", err)
	}

	dg := createDelegationData(
		externalData.stakerPrivKey.PubKey(),
		req.inclusionBlock,
		req.txIndex,
		storedTx,
		slashingTx,
		slashingTxSig,
		externalData.babylonPubKey,
		stakingTxInclusionProof,
		undelegationData,
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

		undelegationData := cl.UndelegationData{
			UnbondingTransaction:         watchedData.UnbondingTx,
			UnbondingTxValue:             btcutil.Amount(watchedData.UnbondingTx.TxOut[0].Value),
			UnbondingTxUnbondingTime:     watchedData.UnbondingTime,
			SlashUnbondingTransaction:    watchedData.SlashingUnbondingTx,
			SlashUnbondingTransactionSig: watchedData.SlashingUnbondingTxSig,
		}

		dg := createDelegationData(
			watchedData.StakerBtcPubKey,
			req.inclusionBlock,
			req.txIndex,
			storedTx,
			watchedData.SlashingTx,
			watchedData.SlashingTxSig,
			watchedData.StakerBabylonPubKey,
			stakingTxInclusionProof,
			&undelegationData,
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
// evidence that covenant members are censoring our staking transactions
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

			params, err := app.babylonClient.Params()

			if err != nil {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"err":           err,
				}).Error("Error getting babylon params")
				// Failed to get params, we cannont do anything, most probably connection error to babylon node
				// we will try again in next iteration
				continue
			}

			// we have enough signatures to submit unbonding tx this means that delegation is active
			if len(di.UndelegationInfo.CovenantUnbondingSignatures) >= int(params.CovenantQuruomThreshold) {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"numSignatures": len(di.UndelegationInfo.CovenantUnbondingSignatures),
				}).Debug("Received enough covenant unbonding signatures on babylon")

				req := &unbondingTxSignaturesConfirmedOnBabylonEvent{
					stakingTxHash:               *stakingTxHash,
					covenantUnbondingSignatures: di.UndelegationInfo.CovenantUnbondingSignatures,
				}

				utils.PushOrQuit[*unbondingTxSignaturesConfirmedOnBabylonEvent](
					app.unbondingTxSignaturesConfirmedOnBabylonEvChan,
					req,
					app.quit,
				)

				return
			} else {
				app.logger.WithFields(logrus.Fields{
					"stakingTxHash": stakingTxHash,
					"numSignatures": len(di.UndelegationInfo.CovenantUnbondingSignatures),
					"required":      params.CovenantQuruomThreshold,
				}).Debug("Received not enough covenant unbonding signatures on babylon")
			}

		case <-app.quit:
			return
		}
	}
}

func (app *StakerApp) finalityProviderExists(fpPk *btcec.PublicKey) error {
	if fpPk == nil {
		return fmt.Errorf("provided finality provider public key is nil")
	}

	_, err := app.babylonClient.QueryFinalityProvider(fpPk)

	if err != nil {
		return fmt.Errorf("error checking if finality provider exists on babylon chain: %w", err)
	}

	return nil
}
