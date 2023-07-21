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
	// DefaultBtcFee Relativly large fee 25 sat/byte to be used for estimating fees.
	// This is to be sure that tx will be confirmed in reasonable time.
	// It is also default fee if dynamic fee estimation fails
	DefaultBtcFee = chainfee.SatPerKVByte(25 * 1000)

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
	estimator chainfee.Estimator
}

func NewDynamicBtcFeeEstimator(
	cfg *scfg.BtcNodeBackendConfig,
	_ *chaincfg.Params,
	_ *logrus.Logger) (*DynamicBtcFeeEstimator, error) {

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
			rpcConfig, cfg.Bitcoind.EstimateMode, DefaultBtcFee.FeePerKWeight(),
		)

		if err != nil {
			return nil, err
		}
		return &DynamicBtcFeeEstimator{
			estimator: est,
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
			rpcConfig, DefaultBtcFee.FeePerKWeight(),
		)

		if err != nil {
			return nil, err
		}

		return &DynamicBtcFeeEstimator{
			estimator: est,
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
		logrus.WithFields(logrus.Fields{
			"err":     err,
			"default": DefaultBtcFee,
		}).Error("Failed to estimate transaction fee. Using default fee")
		return DefaultBtcFee
	}

	return fee.FeePerKVByte()
}

type StaticFeeEstimator struct {
}

var _ FeeEstimator = (*StaticFeeEstimator)(nil)

func NewStaticBtcFeeEstimator() *StaticFeeEstimator {
	return &StaticFeeEstimator{}
}

func (e *StaticFeeEstimator) Start() error {
	return nil
}

func (e *StaticFeeEstimator) Stop() error {
	return nil
}

func (e *StaticFeeEstimator) EstimateFeePerKb() chainfee.SatPerKVByte {
	return DefaultBtcFee
}
