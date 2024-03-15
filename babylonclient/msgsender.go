package babylonclient

import (
	"context"
	"errors"
	"fmt"
	"sync"

	pv "github.com/cosmos/relayer/v2/relayer/provider"
	"golang.org/x/sync/semaphore"

	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/sirupsen/logrus"
)

var (
	ErrBabylonBtcLightClientNotReady = errors.New("babylon btc light client is not ready to receive delegation")
)

type sendDelegationRequest struct {
	utils.Request[*pv.RelayerTxResponse]
	dg                          *DelegationData
	requiredInclusionBlockDepth uint64
}

func newSendDelegationRequest(
	dg *DelegationData,
	requiredInclusionBlockDepth uint64,
) sendDelegationRequest {
	return sendDelegationRequest{
		Request:                     utils.NewRequest[*pv.RelayerTxResponse](),
		dg:                          dg,
		requiredInclusionBlockDepth: requiredInclusionBlockDepth,
	}
}

type sendUndelegationRequest struct {
	utils.Request[*pv.RelayerTxResponse]
	stakingTxHash *chainhash.Hash
	ur            *UndelegationRequest
}

func newSendUndelegationRequest(
	ur *UndelegationRequest,
) sendUndelegationRequest {
	return sendUndelegationRequest{
		Request:       utils.NewRequest[*pv.RelayerTxResponse](),
		ur:            ur,
		stakingTxHash: &ur.StakingTxHash,
	}
}

// BabylonMsgSender is responsible for sending delegation and undelegation requests to babylon
// It makes sure:
// - that babylon is ready for either delgetion or undelegation
// - only one messegae is sent to babylon at a time
type BabylonMsgSender struct {
	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
	quit      chan struct{}

	cl                          BabylonClient
	logger                      *logrus.Logger
	sendDelegationRequestChan   chan *sendDelegationRequest
	sendUndelegationRequestChan chan *sendUndelegationRequest
	s                           *semaphore.Weighted
}

func NewBabylonMsgSender(
	cl BabylonClient,
	logger *logrus.Logger,
	maxConcurrentTransactions uint32,
) *BabylonMsgSender {
	s := semaphore.NewWeighted(int64(maxConcurrentTransactions))
	return &BabylonMsgSender{
		quit:                        make(chan struct{}),
		cl:                          cl,
		logger:                      logger,
		sendDelegationRequestChan:   make(chan *sendDelegationRequest),
		sendUndelegationRequestChan: make(chan *sendUndelegationRequest),
		s:                           s,
	}
}

func (b *BabylonMsgSender) Start() {
	b.startOnce.Do(func() {
		b.wg.Add(1)
		go b.handleSentToBabylon()
	})
}

func (b *BabylonMsgSender) Stop() {
	b.stopOnce.Do(func() {
		close(b.quit)
		b.wg.Wait()
	})
}

// isBabylonBtcLcReady checks if Babylon BTC light client is ready to receive delegation
func (b *BabylonMsgSender) isBabylonBtcLcReady(
	requiredInclusionBlockDepth uint64,
	req *DelegationData,
) error {
	depth, err := b.cl.QueryHeaderDepth(req.StakingTransactionInclusionBlockHash)

	if err != nil {
		// If header is not known to babylon, or it is on LCFork, then most probably
		// lc is not up to date. We should retry sending delegation after some time.
		if errors.Is(err, ErrHeaderNotKnownToBabylon) || errors.Is(err, ErrHeaderOnBabylonLCFork) {
			return fmt.Errorf("btc light client error %s: %w", err.Error(), ErrBabylonBtcLightClientNotReady)
		}

		// got some unknown error, return it to the caller
		return fmt.Errorf("error while getting delegation data: %w", err)
	}

	if depth < requiredInclusionBlockDepth {
		return fmt.Errorf("btc lc not ready, required depth: %d, current depth: %d: %w", requiredInclusionBlockDepth, depth, ErrBabylonBtcLightClientNotReady)
	}

	return nil
}

func (m *BabylonMsgSender) sendDelegationAsync(stakingTxHash *chainhash.Hash, req *sendDelegationRequest) {
	// do not check the error, as only way for it to return err is if provided context would be cancelled
	// which can't happen here
	_ = m.s.Acquire(context.Background(), 1)
	m.wg.Add(1)
	go func() {
		defer m.s.Release(1)
		defer m.wg.Done()
		// TODO pass context to delegate
		m.logger.Info("Sending delegation to babylon")
		txResp, err := m.cl.Delegate(req.dg)
		m.logger.Info("Delegation sent to babylon and included in block")

		if err != nil {
			if errors.Is(err, ErrInvalidBabylonExecution) {
				m.logger.WithFields(logrus.Fields{
					"btcTxHash":          stakingTxHash,
					"babylonTxHash":      txResp.TxHash,
					"babylonBlockHeight": txResp.Height,
					"babylonErrorCode":   txResp.Code,
				}).Error("Invalid delegation data sent to babylon")
			}

			m.logger.WithFields(logrus.Fields{
				"btcTxHash": stakingTxHash,
				"err":       err,
			}).Error("Error while sending delegation data to babylon")

			req.ErrorChan() <- fmt.Errorf("failed to send delegation for tx with hash: %s: %w", stakingTxHash.String(), err)
		}
		m.logger.Info("putting response on the channel")
		req.ResultChan() <- txResp
	}()
}

func (m *BabylonMsgSender) sendUndelegationAsync(stakingTxHash *chainhash.Hash, req *sendUndelegationRequest) {
	// do not check the error, as only way for it to return err is if provided context would be cancelled
	// which can't happen here
	_ = m.s.Acquire(context.Background(), 1)
	m.wg.Add(1)
	go func() {
		defer m.s.Release(1)
		defer m.wg.Done()
		// TODO pass context to undelegate
		txResp, err := m.cl.Undelegate(req.ur)

		if err != nil {
			if errors.Is(err, ErrInvalidBabylonExecution) {
				// Additional logging if for some reason we send unbonding request which was
				// accepted by babylon, but failed execution
				m.logger.WithFields(logrus.Fields{
					"btcTxHash":          req.stakingTxHash.String(),
					"babylonTxHash":      txResp.TxHash,
					"babylonBlockHeight": txResp.Height,
					"babylonErrorCode":   txResp.Code,
				}).Error("Invalid delegation data sent to babylon")
			}

			m.logger.WithFields(logrus.Fields{
				"btcTxHash": req.stakingTxHash,
				"err":       err,
			}).Error("Error while sending undelegation data to babylon")

			req.ErrorChan() <- fmt.Errorf("failed to send unbonding for delegation with staking hash:%s:%w", req.stakingTxHash.String(), err)
		}

		req.ResultChan() <- txResp
	}()
}

func (m *BabylonMsgSender) handleSentToBabylon() {
	defer m.wg.Done()
	for {
		select {
		case req := <-m.sendDelegationRequestChan:
			stakingTxHash := req.dg.StakingTransaction.TxHash()

			err := m.isBabylonBtcLcReady(
				req.requiredInclusionBlockDepth,
				req.dg,
			)

			if err != nil {
				m.logger.WithFields(logrus.Fields{
					"btcTxHash": stakingTxHash,
					"err":       err,
				}).Error("Cannot send delegation request to babylon")

				req.ErrorChan() <- err
				continue
			}

			m.sendDelegationAsync(&stakingTxHash, req)

		case req := <-m.sendUndelegationRequestChan:
			di, err := m.cl.QueryDelegationInfo(req.stakingTxHash)

			if err != nil {
				req.ErrorChan() <- fmt.Errorf("failed to retrieve delegation info for staking tx with hash: %s: %w", req.stakingTxHash.String(), err)
				continue
			}

			if !di.Active {
				req.ErrorChan() <- fmt.Errorf("cannot sent unbonding request for staking tx with hash: %s, as delegation is not active", req.stakingTxHash.String())
				continue
			}

			if di.UndelegationInfo != nil {
				req.ErrorChan() <- fmt.Errorf("cannot sent unbonding request for staking tx with hash: %s, as unbonding request was already sent", req.stakingTxHash.String())
				continue
			}

			m.sendUndelegationAsync(req.stakingTxHash, req)

		case <-m.quit:
			return
		}
	}
}

func (m *BabylonMsgSender) SendDelegation(
	dg *DelegationData,
	requiredInclusionBlockDepth uint64,
) (*pv.RelayerTxResponse, error) {
	req := newSendDelegationRequest(dg, requiredInclusionBlockDepth)

	return utils.SendRequestAndWaitForResponseOrQuit[*pv.RelayerTxResponse, *sendDelegationRequest](
		&req,
		m.sendDelegationRequestChan,
		m.quit,
	)

}

// TODO: Curenttly not used.
// We may introduce the option for staker to self report unbonding tx to babylon.
func (m *BabylonMsgSender) SendUndelegation(
	ur *UndelegationRequest,
) (*pv.RelayerTxResponse, error) {
	req := newSendUndelegationRequest(ur)

	return utils.SendRequestAndWaitForResponseOrQuit[*pv.RelayerTxResponse, *sendUndelegationRequest](
		&req,
		m.sendUndelegationRequestChan,
		m.quit,
	)
}
