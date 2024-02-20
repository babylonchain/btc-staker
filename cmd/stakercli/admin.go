package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path"

	bbntypes "github.com/babylonchain/babylon/types"

	sdkmath "cosmossdk.io/math"
	babylonApp "github.com/babylonchain/babylon/app"
	staking "github.com/babylonchain/babylon/btcstaking"
	"github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/go-bip39"
	"github.com/jessevdk/go-flags"
	"github.com/urfave/cli"
)

var adminCommands = []cli.Command{
	{
		Name:      "admin",
		ShortName: "ad",
		Usage:     "Different utility and admin commands",
		Category:  "Admin",
		Subcommands: []cli.Command{
			dumpCfgCommand,
			createCosmosKeyringCommand,
			createScriptsCommand,
		},
	},
}

const (
	configFileDirFlag = "config-file-dir"
)

var (
	defaultConfigPath = stakercfg.DefaultConfigFile
)

var dumpCfgCommand = cli.Command{
	Name:      "dump-config",
	ShortName: "dc",
	Usage:     "Dump default configuration file.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  configFileDirFlag,
			Usage: "Path to where the default config file will be dumped",
			Value: defaultConfigPath,
		},
	},
	Action: dumpCfg,
}

func dumpCfg(c *cli.Context) error {
	configPath := c.String(configFileDirFlag)

	if stakercfg.FileExists(configPath) {
		return cli.NewExitError(
			fmt.Sprintf("config already exists under provided path: %s", configPath),
			1,
		)
	}

	dir, _ := path.Split(configPath)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return cli.NewExitError(
				fmt.Sprintf("could not create config directory: %s", err.Error()),
				1,
			)
		}
	}

	defaultConfig := stakercfg.DefaultConfig()
	fileParser := flags.NewParser(&defaultConfig, flags.Default)

	err := flags.NewIniParser(fileParser).WriteFile(configPath, flags.IniIncludeComments|flags.IniIncludeDefaults)

	if err != nil {
		return err
	}

	return nil
}

const (
	mnemonicEntropySize = 256
	secp256k1Type       = "secp256k1"

	chainIdFlag        = "chain-id"
	keyringBackendFlag = "keyring-backend"
	keyNameFlag        = "key-name"
	keyringDir         = "keyring-dir"
)

var (
	defaultBBNconfig = stakercfg.DefaultBBNConfig()
	defaultChainID   = defaultBBNconfig.ChainID
	defaultBackend   = defaultBBNconfig.KeyringBackend
	defaultKeyName   = defaultBBNconfig.Key
	defaultKeyDir    = defaultBBNconfig.KeyDirectory
)

func createKey(name string, kr keyring.Keyring) (*keyring.Record, error) {
	keyringAlgos, _ := kr.SupportedAlgorithms()
	algo, err := keyring.NewSigningAlgoFromString(secp256k1Type, keyringAlgos)
	if err != nil {
		return nil, err
	}

	// read entropy seed straight from tmcrypto.Rand and convert to mnemonic
	entropySeed, err := bip39.NewEntropy(mnemonicEntropySize)
	if err != nil {
		return nil, err
	}

	mnemonic, err := bip39.NewMnemonic(entropySeed)
	if err != nil {
		return nil, err
	}

	record, err := kr.NewAccount(name, mnemonic, "", "", algo)
	if err != nil {
		return nil, err
	}

	return record, nil
}

func createKeyRing(c *cli.Context) error {
	keyringOptions := []keyring.Option{}
	keyringOptions = append(keyringOptions, func(options *keyring.Options) {
		options.SupportedAlgos = keyring.SigningAlgoList{hd.Secp256k1}
		options.SupportedAlgosLedger = keyring.SigningAlgoList{hd.Secp256k1}
	})

	app := babylonApp.NewTmpBabylonApp()

	chainId := c.String(chainIdFlag)
	backend := c.String(keyringBackendFlag)
	keyName := c.String(keyNameFlag)
	keyDir := c.String(keyringDir)

	kb, err := keyring.New(
		chainId,
		backend,
		keyDir,
		nil,
		app.AppCodec(),
		keyringOptions...)

	if err != nil {
		return err
	}

	_, err = createKey(keyName, kb)

	if err != nil {
		return err
	}

	list, err := kb.List()

	if err != nil {
		return err
	}

	fmt.Println("Keyring created! Accounts in keyring:")
	for _, r := range list {
		fmt.Println("-", r.Name)
	}

	return nil
}

var createCosmosKeyringCommand = cli.Command{
	Name:      "create-keyring",
	ShortName: "ck",
	Usage: "Create cosmos keyring with secp256k1 key with an account with provided name." +
		" If account already exists in the keyring, a new address will be created for the given key.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  keyNameFlag,
			Usage: "Name of the key account to be created",
			Value: defaultKeyName,
		},
		cli.StringFlag{
			Name:  keyringBackendFlag,
			Usage: "Backend for keyring",
			Value: defaultBackend,
		},
		cli.StringFlag{
			Name:  chainIdFlag,
			Usage: "Chain ID for which account is created",
			Value: defaultChainID,
		},
		cli.StringFlag{
			Name:  keyringDir,
			Usage: "Directory in which keyring should be created",
			Value: defaultKeyDir,
		},
	},
	Action: createKeyRing,
}

const (
	stakerPrivKeyBase58Flag = "staker-priv-key"
	covenantPks             = "covenant-pks"
	covenantThresholdFlag   = "covenant-threshold"
	SlashingAddressFlag     = "slashing-address"
	SlashingRateFlag        = "slashing-rate"
	SlashingFeeFlag         = "slashing-fee"
	UnbondingFeeFlag        = "unbonding-fee"
	UnbondingTimeFlag       = "unbonding-time"
	StakingTxFlag           = "staking-tx"
)

var createScriptsCommand = cli.Command{
	Name:      "create-scripts",
	ShortName: "cs",
	Usage:     "create all scripts related data from provided data",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     stakerPrivKeyBase58Flag,
			Usage:    "base 58 encoded private key of the staker",
			Required: true,
		},
		cli.StringSliceFlag{
			Name:     fpPksFlag,
			Usage:    "BTC public keys of the finality providers in hex",
			Required: true,
		},
		cli.StringSliceFlag{
			Name:     covenantPks,
			Usage:    "BTC public keys of the finality providers in hex",
			Required: true,
		},
		cli.Uint64Flag{
			Name:     covenantThresholdFlag,
			Usage:    "covenant threshold",
			Required: true,
		},

		cli.Uint64Flag{
			Name:     stakingTimeFlag,
			Usage:    "staking time in blocks",
			Required: true,
		},
		cli.Int64Flag{
			Name:     stakingAmountFlag,
			Usage:    "staking amount in satoshis",
			Required: true,
		},
		cli.StringFlag{
			Name:     StakingTxFlag,
			Usage:    "staking transaction hex encoded",
			Required: false,
		},

		cli.StringFlag{
			Name:     SlashingAddressFlag,
			Usage:    "slashing address",
			Value:    "mhHzxWzJzNKVnvtQ1hMhVUArbsLofSdJ2t",
			Required: false,
		},
		cli.StringFlag{
			Name:     slashingTxChangeAddressFlag,
			Usage:    "BTC address on which the change of the slashing transaction will go. Defaults to staker address.",
			Value:    "mhHzxWzJzNKVnvtQ1hMhVUArbsLofSdJ2t",
			Required: false,
		},
		cli.StringFlag{
			Name:  SlashingRateFlag,
			Usage: "slashing rate",
			Value: "0.1",
		},
		cli.Int64Flag{
			Name:  SlashingFeeFlag,
			Usage: "slashing fee",
			Value: 1000,
		},

		cli.Int64Flag{
			Name:  UnbondingFeeFlag,
			Usage: "unbonding fee",
			Value: 1000,
		},
		cli.Uint64Flag{
			Name:  UnbondingTimeFlag,
			Usage: "unbonding time",
			Value: 1000,
		},
	},
	Action: createScripts,
}

type ScriptResponse struct {
	StakingTxHex                   string `json:"staking_tx_hex"`
	StakingPkScriptHex             string `json:"staking_pk_script_hex"`
	StakingTimeLockPathScriptHex   string `json:"staking_time_lock_path_script_hex"`
	StakingUnbondingPathScriptHex  string `json:"staking_unbonding_path_script_hex"`
	StakingSlashingPathScriptHex   string `json:"staking_slashing_path_script_hex"`
	SlashStakingTxHex              string `json:"slash_staking_tx_hex"`
	SlashStakingSigHex             string `json:"slash_staking_sig_hex"`
	UnbondingTxHex                 string `json:"unbonding_tx_hex"`
	UnbondingPkScriptHex           string `json:"unbonding_pk_script_hex"`
	UnbondingTimeLockPathScriptHex string `json:"unbonding_time_lock_path_script_hex"`
	UnbondingSlashingPathScriptHex string `json:"unbonding_slashing_path_script_hex"`
	SlashUnbondingTxHex            string `json:"slash_unbonding_tx_hex"`
	SlashUnbondingSigHex           string `json:"slash_unbonding_sig_hex"`
}

func stakerKeyFromBase58(key string) (*btcec.PrivateKey, *btcec.PublicKey) {
	stakerBase58Key := base58.Decode(key)
	payload := stakerBase58Key[:len(stakerBase58Key)-4]
	stakerPrivKeyBytes := payload[1:]
	return btcec.PrivKeyFromBytes(stakerPrivKeyBytes)
}

func createScripts(c *cli.Context) error {
	testnetParams := chaincfg.TestNet3Params

	stakerPrivKeyBase58 := c.String(stakerPrivKeyBase58Flag)
	stakerPriv, stakerPubKey := stakerKeyFromBase58(stakerPrivKeyBase58)

	fpPks := c.StringSlice(fpPksFlag)
	covenantPks := c.StringSlice(covenantPks)
	stakingTime := c.Uint64(stakingTimeFlag)
	threshold := c.Uint64(covenantThresholdFlag)
	stakingAmount := c.Int64(stakingAmountFlag)
	slashingFee := c.Int64(SlashingFeeFlag)
	slashingAddressString := c.String(SlashingAddressFlag)
	slashingAddress, err := btcutil.DecodeAddress(slashingAddressString, &testnetParams)
	if err != nil {
		return err
	}

	slashingTxChangeAddressString := c.String(slashingTxChangeAddressFlag)

	slashingChangeAddress, err := btcutil.DecodeAddress(slashingTxChangeAddressString, &testnetParams)

	if err != nil {
		return err
	}

	slashingRate := sdkmath.LegacyMustNewDecFromStr(c.String(SlashingRateFlag))

	var covenantPubKeys []*btcec.PublicKey

	for _, pk := range covenantPks {

		decoded, err := hex.DecodeString(pk)

		if err != nil {
			return err
		}

		covPub, err := schnorr.ParsePubKey(decoded)

		if err != nil {
			return err
		}

		covenantPubKeys = append(covenantPubKeys, covPub)
	}

	var providerPubKeys []*btcec.PublicKey

	for _, pk := range fpPks {
		decoded, err := hex.DecodeString(pk)

		if err != nil {
			return err
		}

		fpPub, err := schnorr.ParsePubKey(decoded)

		if err != nil {
			return err
		}

		providerPubKeys = append(providerPubKeys, fpPub)
	}

	stakingInfo, err := staking.BuildStakingInfo(
		stakerPubKey,
		providerPubKeys,
		covenantPubKeys,
		uint32(threshold),
		uint16(stakingTime),
		btcutil.Amount(stakingAmount),
		&testnetParams,
	)

	if err != nil {
		return err
	}

	stakingTimeLockScript, err := stakingInfo.TimeLockPathSpendInfo()

	if err != nil {
		return err
	}

	stakingUnbondingScript, err := stakingInfo.UnbondingPathSpendInfo()

	if err != nil {
		return err
	}

	stakingSlashingScript, err := stakingInfo.SlashingPathSpendInfo()

	if err != nil {
		return err
	}

	var stakingTx *wire.MsgTx

	stakingTxHex := c.String(StakingTxFlag)

	if stakingTxHex == "" {
		// If user did not provide staking tx we will get it from the staking info and add some bogus input
		stakingTx = wire.NewMsgTx(2)
		zeroHash := chainhash.Hash{}

		// TODO add possiblity so set inputs to match tx exactly
		stakingTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&zeroHash, uint32(0)), nil, nil))
		stakingTx.AddTxOut(stakingInfo.StakingOutput)
	} else {
		// user provided staking tx
		stx, _, err := bbntypes.NewBTCTxFromHex(stakingTxHex)

		if err != nil {
			return err
		}

		stakingTx = stx
	}

	stakingOutputIdx, err := bbntypes.GetOutputIdxInBTCTx(stakingTx, stakingInfo.StakingOutput)

	if err != nil {
		return err
	}

	slashingTx, err := staking.BuildSlashingTxFromStakingTxStrict(
		stakingTx,
		stakingOutputIdx,
		slashingAddress,
		slashingChangeAddress,
		slashingFee,
		slashingRate,
		&testnetParams,
	)

	if err != nil {
		return err
	}

	serializedStakingTx, err := utils.SerializeBtcTransaction(stakingTx)

	if err != nil {
		return err
	}

	serializedSlashingTx, err := utils.SerializeBtcTransaction(slashingTx)

	if err != nil {
		return err
	}

	stakingSlashingSig, err := staking.SignTxWithOneScriptSpendInputFromScript(
		slashingTx,
		stakingTx.TxOut[stakingOutputIdx],
		stakerPriv,
		stakingSlashingScript.RevealedLeaf.Script,
	)

	if err != nil {
		return err
	}

	unbondingTime := c.Uint64(UnbondingTimeFlag)
	unbondingFee := c.Int64(UnbondingFeeFlag)

	unbondingInfo, err := staking.BuildUnbondingInfo(
		stakerPubKey,
		providerPubKeys,
		covenantPubKeys,
		uint32(threshold),
		uint16(unbondingTime),
		btcutil.Amount(stakingAmount-unbondingFee),
		&testnetParams,
	)

	if err != nil {
		return err
	}

	unbondingTimeLockScript, err := unbondingInfo.TimeLockPathSpendInfo()

	if err != nil {
		return err
	}

	unbondingSlashingScript, err := unbondingInfo.SlashingPathSpendInfo()

	if err != nil {
		return err
	}

	stakingTxHash := stakingTx.TxHash()
	unbondingTx := wire.NewMsgTx(2)
	unbondingTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&stakingTxHash, stakingOutputIdx), nil, nil))
	unbondingTx.AddTxOut(unbondingInfo.UnbondingOutput)

	slashUnbondingTx, err := staking.BuildSlashingTxFromStakingTxStrict(
		unbondingTx,
		0,
		slashingAddress,
		slashingChangeAddress,
		slashingFee,
		slashingRate,
		&testnetParams,
	)

	if err != nil {
		return err
	}

	unbondingSlashingSig, err := staking.SignTxWithOneScriptSpendInputFromScript(
		unbondingTx,
		unbondingTx.TxOut[0],
		stakerPriv,
		unbondingSlashingScript.RevealedLeaf.Script,
	)

	if err != nil {
		return err
	}

	serializedUnbondingTx, err := utils.SerializeBtcTransaction(unbondingTx)

	if err != nil {
		return err
	}

	serializedSlashUnbondingTx, err := utils.SerializeBtcTransaction(slashUnbondingTx)

	if err != nil {
		return err
	}

	resp := ScriptResponse{
		StakingTxHex:                   hex.EncodeToString(serializedStakingTx),
		StakingPkScriptHex:             hex.EncodeToString(stakingInfo.StakingOutput.PkScript),
		StakingTimeLockPathScriptHex:   hex.EncodeToString(stakingTimeLockScript.GetPkScriptPath()),
		StakingUnbondingPathScriptHex:  hex.EncodeToString(stakingUnbondingScript.GetPkScriptPath()),
		StakingSlashingPathScriptHex:   hex.EncodeToString(stakingSlashingScript.GetPkScriptPath()),
		SlashStakingTxHex:              hex.EncodeToString(serializedSlashingTx),
		SlashStakingSigHex:             hex.EncodeToString(stakingSlashingSig.Serialize()),
		UnbondingTxHex:                 hex.EncodeToString(serializedUnbondingTx),
		UnbondingPkScriptHex:           hex.EncodeToString(unbondingInfo.UnbondingOutput.PkScript),
		UnbondingTimeLockPathScriptHex: hex.EncodeToString(unbondingTimeLockScript.GetPkScriptPath()),
		UnbondingSlashingPathScriptHex: hex.EncodeToString(unbondingSlashingScript.GetPkScriptPath()),
		SlashUnbondingTxHex:            hex.EncodeToString(serializedSlashUnbondingTx),
		SlashUnbondingSigHex:           hex.EncodeToString(unbondingSlashingSig.Serialize()),
	}

	printRespJSON(resp)
	return nil
}
