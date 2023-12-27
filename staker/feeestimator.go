package staker

import (
	"fmt"

	"github.com/babylonchain/btc-staker/types"

	scfg "github.com/babylonchain/btc-staker/stakercfg"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/sirupsen/logrus"
)

const (
	// DefaultNumBlockForEstimation Default number of blocks to use for fee estimation.
	// 1 means we want our transactions to be confirmed in the next block.
	// TODO: make this configurable ?
	DefaultNumBlockForEstimation = 1
)

type FeeEstimator interface {
	Start() error
	Stop() error
	EstimateFeePerKb() chainfee.SatPerKVByte
}

type DynamicBtcFeeEstimator struct {
	estimator  chainfee.Estimator
	logger     *logrus.Logger
	MinFeeRate chainfee.SatPerKVByte
	MaxFeeRate chainfee.SatPerKVByte
}

func NewDynamicBtcFeeEstimator(
	cfg *scfg.BtcNodeBackendConfig,
	_ *chaincfg.Params,
	logger *logrus.Logger) (*DynamicBtcFeeEstimator, error) {

	minFeeRate := chainfee.SatPerKVByte(cfg.MinFeeRate * 1000)
	maxFeeRate := chainfee.SatPerKVByte(cfg.MaxFeeRate * 1000)

	switch cfg.ActiveNodeBackend {
	case types.BitcoindNodeBackend:
		rpcConfig := rpcclient.ConnConfig{
			Host:                 cfg.Bitcoind.RPCHost,
			User:                 cfg.Bitcoind.RPCUser,
			Pass:                 cfg.Bitcoind.RPCPass,
			DisableConnectOnNew:  true,
			DisableAutoReconnect: false,
			DisableTLS:           true,
			HTTPPostMode:         true,
		}

		// TODO: we should probably create our own estimator backend, as those from lnd
		// have hardcoded loggers, so we do not log stuff to file as we want
		est, err := chainfee.NewBitcoindEstimator(
			rpcConfig, cfg.Bitcoind.EstimateMode, maxFeeRate.FeePerKWeight(),
		)

		if err != nil {
			return nil, err
		}
		return &DynamicBtcFeeEstimator{
			estimator:  est,
			logger:     logger,
			MinFeeRate: minFeeRate,
			MaxFeeRate: maxFeeRate,
		}, nil

	case types.BtcdNodeBackend:
		cert, err := scfg.ReadCertFile(cfg.Btcd.RawRPCCert, cfg.Btcd.RPCCert)

		if err != nil {
			return nil, err
		}

		rpcConfig := rpcclient.ConnConfig{
			Host:                 cfg.Btcd.RPCHost,
			Endpoint:             "ws",
			User:                 cfg.Btcd.RPCUser,
			Pass:                 cfg.Btcd.RPCPass,
			Certificates:         cert,
			DisableTLS:           false,
			DisableConnectOnNew:  true,
			DisableAutoReconnect: false,
		}

		est, err := chainfee.NewBtcdEstimator(
			rpcConfig, maxFeeRate.FeePerKWeight(),
		)

		if err != nil {
			return nil, err
		}

		return &DynamicBtcFeeEstimator{
			estimator:  est,
			logger:     logger,
			MinFeeRate: minFeeRate,
			MaxFeeRate: maxFeeRate,
		}, nil

	default:
		return nil, fmt.Errorf("unknown node backend: %v", cfg.ActiveNodeBackend)
	}
}

var _ FeeEstimator = (*DynamicBtcFeeEstimator)(nil)

func (e *DynamicBtcFeeEstimator) Start() error {
	return e.estimator.Start()
}

func (e *DynamicBtcFeeEstimator) Stop() error {
	return e.estimator.Stop()
}

func (e *DynamicBtcFeeEstimator) EstimateFeePerKb() chainfee.SatPerKVByte {
	fee, err := e.estimator.EstimateFeePerKW(DefaultNumBlockForEstimation)

	if err != nil {
		e.logger.WithFields(logrus.Fields{
			"err":     err,
			"default": e.MaxFeeRate,
		}).Error("Failed to estimate transaction fee using connected btc node. Using max fee from config")
		return e.MaxFeeRate
	}

	estimatedFee := fee.FeePerKVByte()

	if estimatedFee < e.MinFeeRate {
		e.logger.WithFields(logrus.Fields{
			"minFeeRate": e.MinFeeRate,
			"estimated":  estimatedFee,
		}).Debug("Estimated fee is lower than min fee rate. Using min fee rate")
		return e.MinFeeRate
	}

	if estimatedFee > e.MaxFeeRate {
		e.logger.WithFields(logrus.Fields{
			"maxFeeRate": e.MaxFeeRate,
			"estimated":  estimatedFee,
		}).Debug("Estimated fee is higher than max fee rate. Using max fee rate")
		return e.MaxFeeRate
	}

	e.logger.WithFields(logrus.Fields{
		"fee":        estimatedFee,
		"maxFeeRate": e.MaxFeeRate,
		"minFeeRate": e.MinFeeRate,
	}).Debug("Using fee rate estimated by connected btc node")

	return estimatedFee
}

type StaticFeeEstimator struct {
	DefaultFee chainfee.SatPerKVByte
}

var _ FeeEstimator = (*StaticFeeEstimator)(nil)

func NewStaticBtcFeeEstimator(defaultFee chainfee.SatPerKVByte) *StaticFeeEstimator {
	return &StaticFeeEstimator{
		DefaultFee: defaultFee,
	}
}

func (e *StaticFeeEstimator) Start() error {
	return nil
}

func (e *StaticFeeEstimator) Stop() error {
	return nil
}

func (e *StaticFeeEstimator) EstimateFeePerKb() chainfee.SatPerKVByte {
	return e.DefaultFee
}
