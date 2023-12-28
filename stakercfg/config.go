package stakercfg

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/babylonchain/btc-staker/types"
	"go.uber.org/zap"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/jessevdk/go-flags"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/sirupsen/logrus"
)

const (
	defaultDataDirname     = "data"
	defaultTLSCertFilename = "tls.cert"
	defaultTLSKeyFilename  = "tls.key"
	defaultLogLevel        = "info"
	defaultLogDirname      = "logs"
	defaultLogFilename     = "stakerd.log"
	DefaultRPCPort         = 15812
	// DefaultAutogenValidity is the default validity of a self-signed
	// certificate. The value corresponds to 14 months
	// (14 months * 30 days * 24 hours).
	defaultTLSCertDuration = 14 * 30 * 24 * time.Hour
	defaultConfigFileName  = "stakerd.conf"
	defaultFeeMode         = "static"
	// We are using 2 sat/vbyte as default min fee rate, as currently our size estimates
	// for different transaction types are not very accurate and if we would use 1 sat/vbyte (minimum accepted by bitcoin network)
	// we risk into having transactions rejected by the network due to low fee.
	DefaultMinFeeRate = 2
	DefaultMaxFeeRate = 25
)

var (
	//   C:\Users\<username>\AppData\Local\stakerd on Windows
	//   ~/.stakerd on Linux
	//   ~/Library/Application Support/stakerd on MacOS
	DefaultStakerdDir = btcutil.AppDataDir("stakerd", false)

	DefaultConfigFile = filepath.Join(DefaultStakerdDir, defaultConfigFileName)
	defaultNetwork    = "testnet"

	defaultDataDir = filepath.Join(DefaultStakerdDir, defaultDataDirname)
	defaultLogDir  = filepath.Join(DefaultStakerdDir, defaultLogDirname)
)

type ChainConfig struct {
	Network         string `long:"network" description:"network to run on" choice:"regtest" choice:"testnet" choice:"simnet" choice:"signet"`
	SigNetChallenge string `long:"signetchallenge" description:"Connect to a custom signet network defined by this challenge instead of using the global default signet test network -- Can be specified multiple times"`
}

func DefaultChainConfig() ChainConfig {
	return ChainConfig{
		Network: defaultNetwork,
	}
}

type WalletConfig struct {
	WalletName string `long:"walletname" description:"name of the wallet to sign Bitcoin transactions"`
	WalletPass string `long:"walletpassphrase" description:"passphrase to unlock the wallet"`
}

func DefaultWalletConfig() WalletConfig {
	return WalletConfig{
		WalletName: "wallet",
		WalletPass: "walletpass",
	}
}

type WalletRpcConfig struct {
	Host       string `long:"wallethost" description:"location of the wallet rpc server"`
	User       string `long:"walletuser" description:"user auth for the wallet rpc server"`
	Pass       string `long:"walletpassword" description:"password auth for the wallet rpc server"`
	DisableTls bool   `long:"noclienttls" description:"disables tls for the wallet rpc client"`
}

func DefaultWalletRpcConfig() WalletRpcConfig {
	return WalletRpcConfig{
		DisableTls: true,
		Host:       "localhost:18556",
		User:       "rpcuser",
		Pass:       "rpcpass",
	}
}

type JsonRpcServerConfig struct {
	RawRPCListeners []string `long:"rpclisten" description:"Add an interface/port/socket to listen for RPC connections"`
}

type BtcNodeBackendConfig struct {
	Nodetype            string    `long:"nodetype" description:"type of node to connect to {bitcoind, btcd}"`
	WalletType          string    `long:"wallettype" description:"type of wallet to connect to {bitcoind, btcwallet}"`
	FeeMode             string    `long:"feemode" description:"fee mode to use for fee estimation {static, dynamic}. In dynamic mode fee will be estimated using backend node"`
	MinFeeRate          uint64    `long:"minfeerate" description:"minimum fee rate to use for fee estimation in sat/vbyte. If fee estimation by connected btc node returns a lower fee rate, this value will be used instead"`
	MaxFeeRate          uint64    `long:"maxfeerate" description:"maximum fee rate to use for fee estimation in sat/vbyte. If fee estimation by connected btc node returns a higher fee rate, this value will be used instead. It is also used as fallback if fee estimation by connected btc node fails and as fee rate in case of static estimator"`
	Btcd                *Btcd     `group:"btcd" namespace:"btcd"`
	Bitcoind            *Bitcoind `group:"bitcoind" namespace:"bitcoind"`
	EstimationMode      types.FeeEstimationMode
	ActiveNodeBackend   types.SupportedNodeBackend
	ActiveWalletBackend types.SupportedWalletBackend
}

func DefaultBtcNodeBackendConfig() BtcNodeBackendConfig {
	btcdConfig := DefaultBtcdConfig()
	bitcoindConfig := DefaultBitcoindConfig()
	return BtcNodeBackendConfig{
		Nodetype:   "btcd",
		WalletType: "btcwallet",
		FeeMode:    defaultFeeMode,
		MinFeeRate: DefaultMinFeeRate,
		MaxFeeRate: DefaultMaxFeeRate,
		Btcd:       &btcdConfig,
		Bitcoind:   &bitcoindConfig,
	}
}

type StakerConfig struct {
	BabylonStallingInterval  time.Duration `long:"babylonstallinginterval" description:"The interval for Babylon node BTC light client to catch up with the real chain before re-sending delegation request"`
	UnbondingTxCheckInterval time.Duration `long:"unbondingtxcheckinterval" description:"The interval for staker whether delegation received all covenant signatures"`
	ExitOnCriticalError      bool          `long:"exitoncriticalerror" description:"Exit stakerd on critical error"`
}

func DefaultStakerConfig() StakerConfig {
	return StakerConfig{
		BabylonStallingInterval:  1 * time.Minute,
		UnbondingTxCheckInterval: 30 * time.Second,
		ExitOnCriticalError:      true,
	}
}

type Config struct {
	DebugLevel string `long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, fatal}"`
	StakerdDir string `long:"stakerddir" description:"The base directory that contains staker's data, logs, configuration file, etc."`
	ConfigFile string `long:"configfile" description:"Path to configuration file"`
	DataDir    string `long:"datadir" description:"The directory to store staker's data within"`
	LogDir     string `long:"logdir" description:"Directory to log output."`
	CPUProfile string `long:"cpuprofile" description:"Write CPU profile to the specified file"`
	Profile    string `long:"profile" description:"Enable HTTP profiling on either a port or host:port"`
	DumpCfg    bool   `long:"dumpcfg" description:"If config filr does not exist, create it with current settings"`

	WalletConfig *WalletConfig `group:"walletconfig" namespace:"walletconfig"`

	WalletRpcConfig *WalletRpcConfig `group:"walletrpcconfig" namespace:"walletrpcconfig"`

	ChainConfig *ChainConfig `group:"chain" namespace:"chain"`

	BtcNodeBackendConfig *BtcNodeBackendConfig `group:"btcnodebackend" namespace:"btcnodebackend"`

	BabylonConfig *BBNConfig `group:"babylon" namespace:"babylon"`

	DBConfig *DBConfig `group:"dbconfig" namespace:"dbconfig"`

	StakerConfig *StakerConfig `group:"stakerconfig" namespace:"stakerconfig"`

	JsonRpcServerConfig *JsonRpcServerConfig

	ActiveNetParams chaincfg.Params

	RpcListeners []net.Addr
}

func DefaultConfig() Config {
	rpcConf := DefaultWalletRpcConfig()
	walletConf := DefaultWalletConfig()
	chainCfg := DefaultChainConfig()
	nodeBackendCfg := DefaultBtcNodeBackendConfig()
	bbnConfig := DefaultBBNConfig()
	dbConfig := DefaultDBConfig()
	stakerConfig := DefaultStakerConfig()
	return Config{
		StakerdDir:           DefaultStakerdDir,
		ConfigFile:           DefaultConfigFile,
		DataDir:              defaultDataDir,
		DebugLevel:           defaultLogLevel,
		LogDir:               defaultLogDir,
		WalletConfig:         &walletConf,
		WalletRpcConfig:      &rpcConf,
		ChainConfig:          &chainCfg,
		BtcNodeBackendConfig: &nodeBackendCfg,
		BabylonConfig:        &bbnConfig,
		DBConfig:             &dbConfig,
		StakerConfig:         &stakerConfig,
	}
}

// usageError is an error type that signals a problem with the supplied flags.
type usageError struct {
	err error
}

// Error returns the error string.
//
// NOTE: This is part of the error interface.
func (u *usageError) Error() string {
	return u.err.Error()
}

// LoadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
//  1. Start with a default config with sane settings
//  2. Pre-parse the command line to check for an alternative config file
//  3. Load configuration file overwriting defaults with any specified options
//  4. Parse CLI options and overwrite/add any specified options
func LoadConfig() (*Config, *logrus.Logger, *zap.Logger, error) {
	// Pre-parse the command line options to pick up an alternative config
	// file.
	preCfg := DefaultConfig()

	if _, err := flags.Parse(&preCfg); err != nil {
		return nil, nil, nil, err
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)

	// If the config file path has not been modified by the user, then
	// we'll use the default config file path. However, if the user has
	// modified their default dir, then we should assume they intend to use
	// the config file within it.
	configFileDir := CleanAndExpandPath(preCfg.StakerdDir)
	configFilePath := CleanAndExpandPath(preCfg.ConfigFile)
	switch {
	case configFileDir != DefaultStakerdDir &&
		configFilePath == DefaultConfigFile:

		configFilePath = filepath.Join(
			configFileDir, defaultConfigFileName,
		)

	// User did specify an explicit --configfile, so we check that it does
	// exist under that path to avoid surprises.
	case configFilePath != DefaultConfigFile:
		if !FileExists(configFilePath) {
			return nil, nil, nil, fmt.Errorf("specified config file does "+
				"not exist in %s", configFilePath)
		}
	}

	// Next, load any additional configuration options from the file.
	var configFileError error
	cfg := preCfg
	fileParser := flags.NewParser(&cfg, flags.Default)
	err := flags.NewIniParser(fileParser).ParseFile(configFilePath)
	if err != nil {
		// If it's a parsing related error, then we'll return
		// immediately, otherwise we can proceed as possibly the config
		// file doesn't exist which is OK.
		if _, ok := err.(*flags.IniError); ok {
			return nil, nil, nil, err
		}

		configFileError = err
	}

	// Finally, parse the remaining command line options again to ensure
	// they take precedence.
	flagParser := flags.NewParser(&cfg, flags.Default)
	if _, err := flagParser.Parse(); err != nil {
		return nil, nil, nil, err
	}

	cfgLogger := logrus.New()
	cfgLogger.Out = os.Stdout
	// Make sure everything we just loaded makes sense.
	cleanCfg, err := ValidateConfig(cfg)
	if err != nil {
		// Log help message in case of usage error.
		if _, ok := err.(*usageError); ok {
			cfgLogger.Warnf("Incorrect usage: %v", usageMessage)
		}

		cfgLogger.Warnf("Error validating config: %v", err)
		return nil, nil, nil, err
	}

	// ignore error here as we already validated the value
	logRuslLevel, _ := logrus.ParseLevel(cleanCfg.DebugLevel)

	// TODO: Add log rotation
	// At this point we know config is valid, create logger which also log to file
	logFilePath := filepath.Join(cleanCfg.LogDir, defaultLogFilename)
	f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, nil, nil, err
	}
	mw := io.MultiWriter(os.Stdout, f)

	cfgLogger.Out = mw
	cfgLogger.Level = logRuslLevel

	// Warn about missing config file only after all other configuration is
	// done. This prevents the warning on help messages and invalid
	// options.  Note this should go directly before the return.
	if configFileError != nil {
		cfgLogger.Warnf("%v", configFileError)
		if cleanCfg.DumpCfg {
			cfgLogger.Infof("Writing configuration file to %s", configFilePath)
			fileParser := flags.NewParser(&cfg, flags.Default)
			err := flags.NewIniParser(fileParser).WriteFile(configFilePath, flags.IniIncludeComments|flags.IniIncludeDefaults)
			if err != nil {
				cfgLogger.Warnf("Error writing configuration file: %v", err)
				return nil, nil, nil, err
			}
		}
	}

	// Zap logger for rpc client
	// TODO: Migrate fully to zap
	zapLogger, err := NewRootLogger("console", cleanCfg.DebugLevel)
	if err != nil {
		return nil, nil, nil, err
	}

	return cleanCfg, cfgLogger, zapLogger, nil
}

// ValidateConfig check the given configuration to be sane. This makes sure no
// illegal values or combination of values are set. All file system paths are
// normalized. The cleaned up config is returned on success.
func ValidateConfig(cfg Config) (*Config, error) {
	// If the provided stakerd directory is not the default, we'll modify the
	// path to all of the files and directories that will live within it.
	stakerdDir := CleanAndExpandPath(cfg.StakerdDir)
	if stakerdDir != DefaultStakerdDir {
		cfg.DataDir = filepath.Join(stakerdDir, defaultDataDirname)
		cfg.LogDir = filepath.Join(stakerdDir, defaultLogDirname)
	}

	funcName := "ValidateConfig"
	mkErr := func(format string, args ...interface{}) error {
		return fmt.Errorf(funcName+": "+format, args...)
	}
	makeDirectory := func(dir string) error {
		err := os.MkdirAll(dir, 0700)
		if err != nil {
			// Show a nicer error message if it's because a symlink
			// is linked to a directory that does not exist
			// (probably because it's not mounted).
			if e, ok := err.(*os.PathError); ok && os.IsExist(err) {
				link, lerr := os.Readlink(e.Path)
				if lerr == nil {
					str := "is symlink %s -> %s mounted?"
					err = fmt.Errorf(str, e.Path, link)
				}
			}

			str := "Failed to create stakerd directory '%s': %v"
			return mkErr(str, dir, err)
		}

		return nil
	}

	// As soon as we're done parsing configuration options, ensure all
	// paths to directories and files are cleaned and expanded before
	// attempting to use them later on.
	cfg.DataDir = CleanAndExpandPath(cfg.DataDir)
	cfg.LogDir = CleanAndExpandPath(cfg.LogDir)

	// Multiple networks can't be selected simultaneously.  Count number of
	// network flags passed; assign active network params
	// while we're at it.
	switch cfg.ChainConfig.Network {
	case "testnet":
		cfg.ActiveNetParams = chaincfg.TestNet3Params
	case "regtest":
		cfg.ActiveNetParams = chaincfg.RegressionNetParams
	case "simnet":
		cfg.ActiveNetParams = chaincfg.SimNetParams
	case "signet":
		cfg.ActiveNetParams = chaincfg.SigNetParams

		// Let the user overwrite the default signet parameters.
		// The challenge defines the actual signet network to
		// join and the seed nodes are needed for network
		// discovery.
		sigNetChallenge := chaincfg.DefaultSignetChallenge
		sigNetSeeds := chaincfg.DefaultSignetDNSSeeds
		if cfg.ChainConfig.SigNetChallenge != "" {
			challenge, err := hex.DecodeString(
				cfg.ChainConfig.SigNetChallenge,
			)
			if err != nil {
				return nil, mkErr("Invalid signet challenge, "+
					"hex decode failed: %v", err)
			}
			sigNetChallenge = challenge
		}

		chainParams := chaincfg.CustomSignetParams(
			sigNetChallenge, sigNetSeeds,
		)
		cfg.ActiveNetParams = chainParams
	default:
		return nil, mkErr(fmt.Sprintf("invalid network: %v",
			cfg.ChainConfig.Network))
	}

	nodeBackend, err := types.NewNodeBackend(cfg.BtcNodeBackendConfig.Nodetype)
	if err != nil {
		return nil, mkErr("error getting node backend: %v", err)
	}
	cfg.BtcNodeBackendConfig.ActiveNodeBackend = nodeBackend

	walletBackend, err := types.NewWalletBackend(cfg.BtcNodeBackendConfig.WalletType)
	if err != nil {
		return nil, mkErr("error getting wallet backend: %v", err)
	}
	cfg.BtcNodeBackendConfig.ActiveWalletBackend = walletBackend

	switch cfg.BtcNodeBackendConfig.FeeMode {
	case "static":
		cfg.BtcNodeBackendConfig.EstimationMode = types.StaticFeeEstimation
	case "dynamic":
		cfg.BtcNodeBackendConfig.EstimationMode = types.DynamicFeeEstimation
	default:
		return nil, mkErr(fmt.Sprintf("invalid fee estimation mode: %s", cfg.BtcNodeBackendConfig.Nodetype))
	}

	if cfg.BtcNodeBackendConfig.MinFeeRate == 0 {
		return nil, mkErr("minfeerate rate must be greater than 0")
	}

	if cfg.BtcNodeBackendConfig.MaxFeeRate == 0 {
		return nil, mkErr("maxfeerate rate must be greater than 0")
	}

	if cfg.BtcNodeBackendConfig.MinFeeRate > cfg.BtcNodeBackendConfig.MaxFeeRate {
		return nil, mkErr(fmt.Sprintf("minfeerate must be less or equal maxfeerate. minfeerate: %d, maxfeerate: %d", cfg.BtcNodeBackendConfig.MinFeeRate, cfg.BtcNodeBackendConfig.MaxFeeRate))
	}

	// TODO: Validate node host and port
	// TODO: Validate babylon config!

	// Validate profile port or host:port.
	if cfg.Profile != "" {
		str := "%s: The profile port must be between 1024 and 65535"

		// Try to parse Profile as a host:port.
		_, hostPort, err := net.SplitHostPort(cfg.Profile)
		if err == nil {
			// Determine if the port is valid.
			profilePort, err := strconv.Atoi(hostPort)
			if err != nil || profilePort < 1024 || profilePort > 65535 {
				return nil, &usageError{mkErr(str)}
			}
		} else {
			// Try to parse Profile as a port.
			profilePort, err := strconv.Atoi(cfg.Profile)
			if err != nil || profilePort < 1024 || profilePort > 65535 {
				return nil, &usageError{mkErr(str)}
			}

			// Since the user just set a port, we will serve debugging
			// information over localhost.
			cfg.Profile = net.JoinHostPort("127.0.0.1", cfg.Profile)
		}
	}

	// Create the stakerd directory and all other sub-directories if they
	// don't already exist. This makes sure that directory trees are also
	// created for files that point to outside the stakerddir.
	dirs := []string{
		stakerdDir, cfg.DataDir, cfg.LogDir,
	}
	for _, dir := range dirs {
		if err := makeDirectory(dir); err != nil {
			return nil, err
		}
	}

	// At least one RPCListener is required. So listen on localhost per
	// default.
	if len(cfg.JsonRpcServerConfig.RawRPCListeners) == 0 {
		addr := fmt.Sprintf("localhost:%d", DefaultRPCPort)
		cfg.JsonRpcServerConfig.RawRPCListeners = append(
			cfg.JsonRpcServerConfig.RawRPCListeners, addr,
		)
	}

	_, err = logrus.ParseLevel(cfg.DebugLevel)

	if err != nil {
		return nil, mkErr("error parsing debuglevel: %v", err)
	}

	// Add default port to all RPC listener addresses if needed and remove
	// duplicate addresses.
	cfg.RpcListeners, err = lncfg.NormalizeAddresses(
		cfg.JsonRpcServerConfig.RawRPCListeners, strconv.Itoa(DefaultRPCPort),
		net.ResolveTCPAddr,
	)

	if err != nil {
		return nil, mkErr("error normalizing RPC listen addrs: %v", err)
	}

	// All good, return the sanitized result.
	return &cfg, nil
}

// FileExists reports whether the named file or directory exists.
// This function is taken from https://github.com/btcsuite/btcd
func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// CleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func CleanAndExpandPath(path string) string {
	if path == "" {
		return ""
	}

	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		var homeDir string
		u, err := user.Current()
		if err == nil {
			homeDir = u.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}
