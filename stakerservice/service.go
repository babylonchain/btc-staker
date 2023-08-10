package stakerservice

import (
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	str "github.com/babylonchain/btc-staker/staker"
	scfg "github.com/babylonchain/btc-staker/stakercfg"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/cometbft/cometbft/libs/log"
	rpc "github.com/cometbft/cometbft/rpc/jsonrpc/server"
	rpctypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"

	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/sirupsen/logrus"
)

const (
	defaultOffset = 0
	defaultLimit  = 50
	maxLimit      = 100
)

type RoutesMap map[string]*rpc.RPCFunc

type StakerService struct {
	started int32

	config      *scfg.Config
	staker      *str.StakerApp
	logger      *logrus.Logger
	db          kvdb.Backend
	interceptor signal.Interceptor
}

func NewStakerService(
	c *scfg.Config,
	s *str.StakerApp,
	l *logrus.Logger,
	sig signal.Interceptor,
	db kvdb.Backend,
) *StakerService {
	return &StakerService{
		config:      c,
		staker:      s,
		logger:      l,
		interceptor: sig,
		db:          db,
	}
}

func (s *StakerService) health(_ *rpctypes.Context) (*ResultHealth, error) {
	return &ResultHealth{}, nil
}

func (s *StakerService) stake(_ *rpctypes.Context,
	stakerAddress string,
	stakingAmount int64,
	validatorPk string,
	stakingTimeBlocks int64,
) (*ResultStake, error) {

	if stakingAmount <= 0 {
		return nil, fmt.Errorf("staking amount must be positive")
	}

	amount := btcutil.Amount(stakingAmount)

	address, err := btcutil.DecodeAddress(stakerAddress, &s.config.ActiveNetParams)

	if err != nil {
		return nil, err
	}

	validatorPkBytes, err := hex.DecodeString(validatorPk)

	if err != nil {
		return nil, err
	}

	valSchnorrKey, err := schnorr.ParsePubKey(validatorPkBytes)

	if err != nil {
		return nil, err
	}

	if stakingTimeBlocks <= 0 || stakingTimeBlocks > math.MaxUint16 {
		return nil, fmt.Errorf("staking time must be positive and lower than %d", math.MaxUint16)
	}

	stakingTimeUint16 := uint16(stakingTimeBlocks)

	stakingTxHash, err := s.staker.StakeFunds(address, amount, valSchnorrKey, stakingTimeUint16)

	if err != nil {
		return nil, err
	}

	return &ResultStake{
		TxHash: stakingTxHash.String(),
	}, nil
}

func (s *StakerService) stakingDetails(_ *rpctypes.Context,
	stakingTxHash string) (*StakingDetails, error) {

	txHash, err := chainhash.NewHashFromStr(stakingTxHash)

	if err != nil {
		return nil, err
	}

	storedTx, err := s.staker.GetStoredTransaction(txHash)

	if err != nil {
		return nil, err
	}

	return &StakingDetails{
		StakingTxHash: storedTx.BtcTx.TxHash().String(),
		StakerAddress: storedTx.StakerAddress,
		StakingScript: hex.EncodeToString(storedTx.TxScript),
		StakingState:  storedTx.State.String(),
	}, nil
}

func (s *StakerService) spendStakingTx(_ *rpctypes.Context,
	stakingTxHash string) (*SpendTxDetails, error) {
	txHash, err := chainhash.NewHashFromStr(stakingTxHash)

	if err != nil {
		return nil, err
	}

	spendTxHash, value, err := s.staker.SpendStakingOutput(txHash)

	if err != nil {
		return nil, err
	}

	txValue := strconv.FormatInt(int64(*value), 10)

	return &SpendTxDetails{
		TxHash:  spendTxHash.String(),
		TxValue: txValue,
	}, nil
}

func (s *StakerService) listOutputs(_ *rpctypes.Context) (*OutputsResponse, error) {

	outputs, err := s.staker.ListUnspentOutputs()

	if err != nil {
		return nil, err
	}

	var outputDetails []OutputDetail

	for _, output := range outputs {
		outputDetails = append(outputDetails, OutputDetail{
			Address: output.Address,
			Amount:  output.Amount.String(),
		})
	}

	return &OutputsResponse{
		Outputs: outputDetails,
	}, nil
}

type PageParams struct {
	Offset uint64
	Limit  uint64
}

func getPageParams(offsetPtr *int, limitPtr *int) PageParams {
	var limit uint64

	if limitPtr == nil {
		limit = defaultLimit
	} else {
		limit = uint64(*limitPtr)
	}

	if limit > maxLimit {
		limit = maxLimit
	}

	var offset uint64

	if offsetPtr == nil {
		offset = defaultOffset
	} else {
		offset = uint64(*offsetPtr)
	}

	return PageParams{
		Offset: offset,
		Limit:  limit,
	}
}

func (s *StakerService) validators(_ *rpctypes.Context, offset, limit *int) (*ValidatorsResponse, error) {

	pageParams := getPageParams(offset, limit)

	validatorsResp, err := s.staker.ListActiveValidators(pageParams.Limit, pageParams.Offset)

	if err != nil {
		return nil, err
	}

	var validatorInfos []ValidatorInfoResponse

	for _, validator := range validatorsResp.Validators {
		v := ValidatorInfoResponse{
			BabylonPublicKey: hex.EncodeToString(validator.BabylonPk.Key),
			BtcPublicKey:     hex.EncodeToString(schnorr.SerializePubKey(&validator.BtcPk)),
		}

		validatorInfos = append(validatorInfos, v)
	}

	totalCount := strconv.FormatUint(validatorsResp.Total, 10)

	return &ValidatorsResponse{
		Validators:          validatorInfos,
		TotalValidatorCount: totalCount,
	}, nil
}

func (s *StakerService) listStakingTransactions(_ *rpctypes.Context, offset, limit *int) (*ListStakingTransactionsResponse, error) {
	pageParams := getPageParams(offset, limit)

	txResult, err := s.staker.StoredTransactions(pageParams.Limit, pageParams.Offset)

	if err != nil {
		return nil, err
	}

	var stakingDetails []StakingDetails

	for _, tx := range txResult.Transactions {
		stakingDetails = append(stakingDetails, StakingDetails{
			StakingTxHash: tx.BtcTx.TxHash().String(),
			StakerAddress: tx.StakerAddress,
			StakingScript: hex.EncodeToString(tx.TxScript),
			StakingState:  tx.State.String(),
		})
	}

	totalCount := strconv.FormatUint(txResult.Total, 10)

	return &ListStakingTransactionsResponse{
		Transactions:          stakingDetails,
		TotalTransactionCount: totalCount,
	}, nil
}

func (s *StakerService) GetRoutes() RoutesMap {
	return RoutesMap{
		// info AP
		"health": rpc.NewRPCFunc(s.health, ""),
		// staking API
		"stake":                     rpc.NewRPCFunc(s.stake, "stakerAddress,stakingAmount,validatorPk,stakingTimeBlocks"),
		"staking_details":           rpc.NewRPCFunc(s.stakingDetails, "stakingTxHash"),
		"spend_staking_tx":          rpc.NewRPCFunc(s.spendStakingTx, "stakingTxHash"),
		"list_staking_transactions": rpc.NewRPCFunc(s.listStakingTransactions, "offset,limit"),

		// Wallet api
		"list_outputs": rpc.NewRPCFunc(s.listOutputs, ""),

		// Babylon api
		"babylon_validators": rpc.NewRPCFunc(s.validators, "offset,limit"),
	}
}

func (s *StakerService) RunUntilShutdown() error {
	if atomic.AddInt32(&s.started, 1) != 1 {
		return nil
	}

	defer func() {
		s.logger.Info("Shutdown complete")
	}()

	defer func() {
		s.logger.Info("Closing database...")
		s.db.Close()
		s.logger.Info("Database closed")
	}()

	mkErr := func(format string, args ...interface{}) error {
		logFormat := strings.ReplaceAll(format, "%w", "%v")
		s.logger.Errorf("Shutting down because error in main "+
			"method: "+logFormat, args...)
		return fmt.Errorf(format, args...)
	}

	err := s.staker.Start()
	if err != nil {
		return mkErr("error starting staker: %w", err)
	}

	defer func() {
		_ = s.staker.Stop()
		s.logger.Info("staker stop complete")
	}()

	routes := s.GetRoutes()
	// TODO: Add staker service dedicated config to define those values
	config := rpc.DefaultConfig()
	// This way logger will log to stdout and file
	// TODO: investigate if we can use logrus directly to pass it to rpcserver
	rpcLogger := log.NewTMLogger(s.logger.Writer())

	listeners := make([]net.Listener, len(s.config.RpcListeners))
	for i, listenAddr := range s.config.RpcListeners {
		listenAddressStr := listenAddr.Network() + "://" + listenAddr.String()
		mux := http.NewServeMux()
		rpc.RegisterRPCFuncs(mux, routes, rpcLogger)

		listener, err := rpc.Listen(
			listenAddressStr,
			config,
		)

		if err != nil {
			return mkErr("unable to listen on %s: %v",
				listenAddressStr, err)
		}

		defer func() {
			err := listener.Close()
			if err != nil {
				s.logger.Error("Error closing listener", "err", err)
			}
		}()

		// Start standard HTTP server serving json-rpc
		// TODO: Add additional middleware, like CORS, TLS, etc.
		// TODO: Consider we need some websockets for some notications
		go func() {
			s.logger.Debug("Starting Json RPC HTTP server ", "address", listenAddressStr)

			err := rpc.Serve(
				listener,
				mux,
				rpcLogger,
				config,
			)

			s.logger.Error("Json RPC HTTP server stopped ", "err", err)
		}()

		listeners[i] = listener
	}

	s.logger.Info("Staker Service fully started")

	// Wait for shutdown signal from either a graceful service stop or from
	// the interrupt handler.
	<-s.interceptor.ShutdownChannel()

	s.logger.Info("Received shutdown signal. Stopping...")

	return nil
}
