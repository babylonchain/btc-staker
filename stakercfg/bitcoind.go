package stakercfg

import (
	"time"
)

const (
	// DefaultTxPollingJitter defines the default TxPollingIntervalJitter
	// to be used for bitcoind backend.
	DefaultTxPollingJitter = 0.5
)

// Bitcoind holds the configuration options for the daemon's connection to
// bitcoind.
// copied from: https://github.com/lightningnetwork/lnd
//
//nolint:lll
type Bitcoind struct {
	RPCHost              string        `long:"rpchost" description:"The daemon's rpc listening address"`
	RPCUser              string        `long:"rpcuser" description:"Username for RPC connections"`
	RPCPass              string        `long:"rpcpass" default-mask:"-" description:"Password for RPC connections"`
	ZMQPubRawBlock       string        `long:"zmqpubrawblock" description:"The address listening for ZMQ connections to deliver raw block notifications"`
	ZMQPubRawTx          string        `long:"zmqpubrawtx" description:"The address listening for ZMQ connections to deliver raw transaction notifications"`
	ZMQReadDeadline      time.Duration `long:"zmqreaddeadline" description:"The read deadline for reading ZMQ messages from both the block and tx subscriptions"`
	EstimateMode         string        `long:"estimatemode" description:"The fee estimate mode. Must be either ECONOMICAL or CONSERVATIVE."`
	PrunedNodeMaxPeers   int           `long:"pruned-node-max-peers" description:"The maximum number of peers staker will choose from the backend node to retrieve pruned blocks from. This only applies to pruned nodes."`
	RPCPolling           bool          `long:"rpcpolling" description:"Poll the bitcoind RPC interface for block and transaction notifications instead of using the ZMQ interface"`
	BlockPollingInterval time.Duration `long:"blockpollinginterval" description:"The interval that will be used to poll bitcoind for new blocks. Only used if rpcpolling is true."`
	TxPollingInterval    time.Duration `long:"txpollinginterval" description:"The interval that will be used to poll bitcoind for new tx. Only used if rpcpolling is true."`
}

func DefaultBitcoindConfig() Bitcoind {
	return Bitcoind{
		RPCHost:              "127.0.0.1:8334",
		RPCUser:              "user",
		RPCPass:              "pass",
		RPCPolling:           true,
		BlockPollingInterval: 30 * time.Second,
		TxPollingInterval:    30 * time.Second,
		EstimateMode:         "CONSERVATIVE",
	}
}
