package stakerservice

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	str "github.com/babylonchain/btc-staker/staker"
	scfg "github.com/babylonchain/btc-staker/stakercfg"
	"github.com/cometbft/cometbft/libs/log"
	rpc "github.com/cometbft/cometbft/rpc/jsonrpc/server"
	rpctypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/sirupsen/logrus"
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

func (s *StakerService) health(*rpctypes.Context) (*ResultHealth, error) {
	return &ResultHealth{}, nil
}

func (s *StakerService) GetRoutes() RoutesMap {
	return RoutesMap{
		// info AP
		"health": rpc.NewRPCFunc(s.health, ""),
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
		s.staker.Stop()
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
