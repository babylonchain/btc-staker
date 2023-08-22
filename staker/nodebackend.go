package staker

import (
	"fmt"
	"net"

	"github.com/babylonchain/btc-staker/types"

	scfg "github.com/babylonchain/btc-staker/stakercfg"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/chainntnfs/bitcoindnotify"
	"github.com/lightningnetwork/lnd/chainntnfs/btcdnotify"
	"github.com/lightningnetwork/lnd/channeldb"
)

type NodeBackend struct {
	chainntnfs.ChainNotifier
}

// TODO  This should be moved to a more appropriate place, most probably to config
// and be connected to validation of rpc host/port.
// According to chain.BitcoindConfig docs it should also support tor if node backend
// works over tor.
func BuildDialer(rpcHost string) func(string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		return net.Dial("tcp", rpcHost)
	}
}

func NewNodeBackend(
	cfg *scfg.BtcNodeBackendConfig,
	params *chaincfg.Params,
	hintCache *channeldb.HeightHintCache,
) (*NodeBackend, error) {
	switch cfg.ActiveNodeBackend {
	case types.BitcoindNodeBackend:
		bitcoindCfg := &chain.BitcoindConfig{
			ChainParams:        params,
			Host:               cfg.Bitcoind.RPCHost,
			User:               cfg.Bitcoind.RPCUser,
			Pass:               cfg.Bitcoind.RPCPass,
			Dialer:             BuildDialer(cfg.Bitcoind.RPCHost),
			PrunedModeMaxPeers: cfg.Bitcoind.PrunedNodeMaxPeers,
		}

		if cfg.Bitcoind.RPCPolling {
			bitcoindCfg.PollingConfig = &chain.PollingConfig{
				BlockPollingInterval:    cfg.Bitcoind.BlockPollingInterval,
				TxPollingInterval:       cfg.Bitcoind.TxPollingInterval,
				TxPollingIntervalJitter: scfg.DefaultTxPollingJitter,
			}
		} else {
			bitcoindCfg.ZMQConfig = &chain.ZMQConfig{
				ZMQBlockHost:           cfg.Bitcoind.ZMQPubRawBlock,
				ZMQTxHost:              cfg.Bitcoind.ZMQPubRawTx,
				ZMQReadDeadline:        cfg.Bitcoind.ZMQReadDeadline,
				MempoolPollingInterval: cfg.Bitcoind.TxPollingInterval,
				PollingIntervalJitter:  scfg.DefaultTxPollingJitter,
			}
		}

		bitcoindConn, err := chain.NewBitcoindConn(bitcoindCfg)
		if err != nil {
			return nil, err
		}

		if err := bitcoindConn.Start(); err != nil {
			return nil, fmt.Errorf("unable to connect to "+
				"bitcoind: %v", err)
		}

		chainNotifier := bitcoindnotify.New(
			bitcoindConn, params, hintCache,
			hintCache, blockcache.NewBlockCache(cfg.Bitcoind.BlockCacheSize),
		)

		return &NodeBackend{
			ChainNotifier: chainNotifier,
		}, nil

	case types.BtcdNodeBackend:
		btcdUser := cfg.Btcd.RPCUser
		btcdPass := cfg.Btcd.RPCPass
		btcdHost := cfg.Btcd.RPCHost

		cert, err := scfg.ReadCertFile(cfg.Btcd.RawRPCCert, cfg.Btcd.RPCCert)

		if err != nil {
			return nil, err
		}

		rpcConfig := &rpcclient.ConnConfig{
			Host:                 btcdHost,
			Endpoint:             "ws",
			User:                 btcdUser,
			Pass:                 btcdPass,
			Certificates:         cert,
			DisableTLS:           false,
			DisableConnectOnNew:  true,
			DisableAutoReconnect: false,
		}

		chainNotifier, err := btcdnotify.New(
			rpcConfig, params, hintCache,
			hintCache, blockcache.NewBlockCache(cfg.Btcd.BlockCacheSize),
		)

		if err != nil {
			return nil, err
		}

		return &NodeBackend{
			ChainNotifier: chainNotifier,
		}, nil

	default:
		return nil, fmt.Errorf("unknown node backend: %v", cfg.ActiveNodeBackend)
	}
}
