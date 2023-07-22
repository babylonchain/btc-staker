package staker

import (
	"fmt"
	"github.com/babylonchain/btc-staker/types"
	"net"
	"sync"

	scfg "github.com/babylonchain/btc-staker/stakercfg"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/lightningnetwork/lnd/blockcache"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/chainntnfs/bitcoindnotify"
	"github.com/lightningnetwork/lnd/chainntnfs/btcdnotify"
)

// copied from: https://github.com/lightningnetwork/lnd
// TODO: After introducing database, use real implementation of hint cache backed by database
type mockHintCache struct {
	mu         sync.Mutex
	confHints  map[chainntnfs.ConfRequest]uint32
	spendHints map[chainntnfs.SpendRequest]uint32
}

var _ chainntnfs.SpendHintCache = (*mockHintCache)(nil)
var _ chainntnfs.ConfirmHintCache = (*mockHintCache)(nil)

func (c *mockHintCache) CommitSpendHint(heightHint uint32,
	spendRequests ...chainntnfs.SpendRequest) error {
	fmt.Println("CommitSpendHint", heightHint)

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, spendRequest := range spendRequests {
		c.spendHints[spendRequest] = heightHint
	}
	fmt.Println("CommitSpendHintUnlock", heightHint)

	return nil
}

func (c *mockHintCache) QuerySpendHint(spendRequest chainntnfs.SpendRequest) (uint32, error) {
	fmt.Println("QuerySpendHint")
	c.mu.Lock()
	defer c.mu.Unlock()

	hint, ok := c.spendHints[spendRequest]
	if !ok {
		return 0, chainntnfs.ErrSpendHintNotFound
	}

	return hint, nil
}

func (c *mockHintCache) PurgeSpendHint(spendRequests ...chainntnfs.SpendRequest) error {
	fmt.Println("PurgeSpendHint")
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, spendRequest := range spendRequests {
		delete(c.spendHints, spendRequest)
	}

	return nil
}

func (c *mockHintCache) CommitConfirmHint(heightHint uint32,
	confRequests ...chainntnfs.ConfRequest) error {
	fmt.Println("CommitConfirmHint", heightHint)

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, confRequest := range confRequests {
		c.confHints[confRequest] = heightHint
	}

	fmt.Println("CommitConfirmHintUnlock", heightHint)

	return nil
}

func (c *mockHintCache) QueryConfirmHint(confRequest chainntnfs.ConfRequest) (uint32, error) {
	fmt.Println("queryconfirmhint")
	c.mu.Lock()
	defer c.mu.Unlock()

	hint, ok := c.confHints[confRequest]
	if !ok {
		fmt.Println("not found")
		return 0, chainntnfs.ErrConfirmHintNotFound
	}
	fmt.Println("hint found")

	return hint, nil
}

func (c *mockHintCache) PurgeConfirmHint(confRequests ...chainntnfs.ConfRequest) error {
	fmt.Println("purgeconfirmhint")
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, confRequest := range confRequests {
		delete(c.confHints, confRequest)
	}

	return nil
}

func newMockHintCache() *mockHintCache {
	return &mockHintCache{
		confHints:  make(map[chainntnfs.ConfRequest]uint32),
		spendHints: make(map[chainntnfs.SpendRequest]uint32),
	}
}

type NodeBackend struct {
	chainntnfs.ChainNotifier
}

// TODO  This should be moved to a more appropriate place, most probably to config
// and be connected to validation of rpc host/port.
// According to chain.BitcoindConfig docs it should also support tor if node backend
// works over tor.
func BuildDialer(_ string) func(string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}
}

func NewNodeBackend(
	cfg *scfg.BtcNodeBackendConfig,
	params *chaincfg.Params,
) (*NodeBackend, error) {
	mockHintCache1 := newMockHintCache()
	mockHintCache2 := newMockHintCache()
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
			bitcoindConn, params, mockHintCache1,
			mockHintCache2, blockcache.NewBlockCache(cfg.Bitcoind.BlockCacheSize),
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
			rpcConfig, params, mockHintCache1,
			mockHintCache2, blockcache.NewBlockCache(cfg.Btcd.BlockCacheSize),
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
