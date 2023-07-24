package stakercfg

import (
	"path/filepath"

	"github.com/btcsuite/btcd/btcutil"
)

const (
	defaultBtcdRPCHost        = "127.0.0.1:18334"
	defaultBtcdRPCUser        = "user"
	defaultBtcdRPCPass        = "pass"
	defaultBtcdBlockCacheSize = 20 * 1024 * 1024 // 20 MB
)

var (
	defaultBtcdDir         = btcutil.AppDataDir("btcd", false)
	defaultBtcdRPCCertFile = filepath.Join(defaultBtcdDir, "rpc.cert")
)

// Btcd holds the configuration options for the daemon's connection to btcd.
// copied from: https://github.com/lightningnetwork/lnd
//
//nolint:lll
type Btcd struct {
	RPCHost        string `long:"rpchost" description:"The daemon's rpc listening address. If a port is omitted, then the default port for the selected chain parameters will be used."`
	RPCUser        string `long:"rpcuser" description:"Username for RPC connections"`
	RPCPass        string `long:"rpcpass" description:"Password for RPC connections"`
	RPCCert        string `long:"rpccert" description:"File containing the daemon's certificate file"`
	RawRPCCert     string `long:"rawrpccert" description:"The raw bytes of the daemon's PEM-encoded certificate chain which will be used to authenticate the RPC connection."`
	BlockCacheSize uint64 `long:"block-cache-size" description:"size of the Bitcoin blocks cache"`
}

func DefaultBtcdConfig() Btcd {
	return Btcd{
		RPCHost:        defaultBtcdRPCHost,
		RPCUser:        defaultBtcdRPCUser,
		RPCPass:        defaultBtcdRPCPass,
		RPCCert:        defaultBtcdRPCCertFile,
		BlockCacheSize: defaultBtcdBlockCacheSize,
	}
}
