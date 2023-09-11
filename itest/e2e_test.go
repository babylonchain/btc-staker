//go:build e2e
// +build e2e

package e2etest

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"strconv"

	dc "github.com/babylonchain/btc-staker/stakerservice/client"
	"github.com/babylonchain/btc-staker/utils"

	"github.com/babylonchain/babylon/testutil/datagen"
	bbntypes "github.com/babylonchain/babylon/types"
	btcstypes "github.com/babylonchain/babylon/x/btcstaking/types"
	service "github.com/babylonchain/btc-staker/stakerservice"
	secp256k1 "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"

	staking "github.com/babylonchain/babylon/btcstaking"
	"github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/proto"
	"github.com/babylonchain/btc-staker/staker"
	"github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/types"
	"github.com/babylonchain/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	sttypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// bitcoin params used for testing
var (
	simnetParams     = &chaincfg.SimNetParams
	submitterAddrStr = "bbn1eppc73j56382wjn6nnq3quu5eye4pmm087xfdh"
	babylonTag       = []byte{1, 2, 3, 4}
	babylonTagHex    = hex.EncodeToString(babylonTag)

	// copy of the seed from btcd/integration/rpctest memWallet, this way we can
	// import the same wallet in the btcd wallet
	hdSeed = [chainhash.HashSize]byte{
		0x79, 0xa6, 0x1a, 0xdb, 0xc6, 0xe5, 0xa2, 0xe1,
		0x39, 0xd2, 0x71, 0x3a, 0x54, 0x6e, 0xc7, 0xc8,
		0x75, 0x63, 0x2e, 0x75, 0xf1, 0xdf, 0x9c, 0x3f,
		0xa6, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// current number of active test nodes. This is necessary to replicate btcd rpctest.Harness
	// methods of generating keys i.e with each started btcd node we increment this number
	// by 1, and then use hdSeed || numTestInstances as the seed for generating keys
	numTestInstances = 0

	existingWalletFile = "wallet.db"
	exisitngWalletPass = "pass"
	walletTimeout      = 86400

	eventuallyWaitTimeOut = 10 * time.Second
	eventuallyPollTime    = 500 * time.Millisecond
)

// keyToAddr maps the passed private to corresponding p2pkh address.
func keyToAddr(key *btcec.PrivateKey, net *chaincfg.Params) (btcutil.Address, error) {
	serializedKey := key.PubKey().SerializeCompressed()
	pubKeyAddr, err := btcutil.NewAddressPubKey(serializedKey, net)
	if err != nil {
		return nil, err
	}
	return pubKeyAddr.AddressPubKeyHash(), nil
}

func defaultStakerConfig(btcdCert []byte, btcdHost string) *stakercfg.Config {
	defaultConfig := stakercfg.DefaultConfig()
	// configure node backend
	defaultConfig.BtcNodeBackendConfig.Nodetype = "btcd"
	defaultConfig.BtcNodeBackendConfig.Btcd.RPCHost = btcdHost
	defaultConfig.BtcNodeBackendConfig.Btcd.RawRPCCert = hex.EncodeToString(btcdCert)
	defaultConfig.BtcNodeBackendConfig.Btcd.RPCUser = "user"
	defaultConfig.BtcNodeBackendConfig.Btcd.RPCPass = "pass"
	defaultConfig.BtcNodeBackendConfig.ActiveNodeBackend = types.BtcdNodeBackend
	defaultConfig.BtcNodeBackendConfig.ActiveWalletBackend = types.BtcwalletWalletBackend

	// configure wallet rpc
	defaultConfig.ChainConfig.Network = "simnet"
	defaultConfig.ActiveNetParams = *simnetParams
	// Config setting necessary to connect btcwallet daemon
	defaultConfig.WalletConfig.WalletPass = "pass"

	defaultConfig.WalletRpcConfig.Host = "127.0.0.1:18554"
	defaultConfig.WalletRpcConfig.User = "user"
	defaultConfig.WalletRpcConfig.Pass = "pass"
	defaultConfig.WalletRpcConfig.DisableTls = true

	// Set it to something low to not slow down tests
	defaultConfig.StakerConfig.BabylonStallingInterval = 3 * time.Second

	return &defaultConfig
}

func GetSpendingKeyAndAddress(id uint32) (*btcec.PrivateKey, btcutil.Address, error) {
	var harnessHDSeed [chainhash.HashSize + 4]byte
	copy(harnessHDSeed[:], hdSeed[:])
	// id used for our test wallet is always 0
	binary.BigEndian.PutUint32(harnessHDSeed[:chainhash.HashSize], id)

	hdRoot, err := hdkeychain.NewMaster(harnessHDSeed[:], simnetParams)

	if err != nil {
		return nil, nil, err
	}

	// The first child key from the hd root is reserved as the coinbase
	// generation address.
	coinbaseChild, err := hdRoot.Derive(0)
	if err != nil {
		return nil, nil, err
	}

	coinbaseKey, err := coinbaseChild.ECPrivKey()

	if err != nil {
		return nil, nil, err
	}

	coinbaseAddr, err := keyToAddr(coinbaseKey, simnetParams)
	if err != nil {
		return nil, nil, err
	}

	return coinbaseKey, coinbaseAddr, nil
}

type TestManager struct {
	MinerNode        *rpctest.Harness
	BtcWalletHandler *WalletHandler
	BabylonHandler   *BabylonNodeHandler
	Config           *stakercfg.Config
	Db               kvdb.Backend
	Sa               *staker.StakerApp
	BabylonClient    *babylonclient.BabylonController
	WalletPrivKey    *btcec.PrivateKey
	MinerAddr        btcutil.Address
	serverStopper    *signal.Interceptor
	wg               *sync.WaitGroup
	serviceAddress   string
	StakerClient     *dc.StakerServiceJsonRpcClient
}

type testStakingData struct {
	StakerKey                 *btcec.PublicKey
	StakerBabylonPrivKey      *secp256k1.PrivKey
	StakerBabylonPubKey       *secp256k1.PubKey
	ValidatorBabylonPrivKey   *secp256k1.PrivKey
	ValidatorBabylonPublicKey *secp256k1.PubKey
	ValidatorBtcPrivKey       *btcec.PrivateKey
	ValidatorBtcKey           *btcec.PublicKey
	JuryPrivKey               *btcec.PrivateKey
	JuryKey                   *btcec.PublicKey
	StakingTime               uint16
	StakingAmount             int64
	Script                    []byte
}

func getTestStakingData(t *testing.T, stakerKey *btcec.PublicKey, stakingTime uint16, stakingAmount int64) *testStakingData {
	delegatarPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	juryPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	stakingData, err := staking.NewStakingScriptData(
		stakerKey,
		delegatarPrivKey.PubKey(),
		juryPrivKey.PubKey(),
		stakingTime,
	)

	require.NoError(t, err)

	script, err := stakingData.BuildStakingScript()
	require.NoError(t, err)

	validatorBabylonPrivKey := secp256k1.GenPrivKey()
	validatorBabylonPubKey := validatorBabylonPrivKey.PubKey().(*secp256k1.PubKey)

	stakerBabylonPrivKey := secp256k1.GenPrivKey()
	stakerBabylonPubKey := stakerBabylonPrivKey.PubKey().(*secp256k1.PubKey)

	return &testStakingData{
		StakerKey:                 stakerKey,
		StakerBabylonPrivKey:      stakerBabylonPrivKey,
		StakerBabylonPubKey:       stakerBabylonPubKey,
		ValidatorBabylonPrivKey:   validatorBabylonPrivKey,
		ValidatorBabylonPublicKey: validatorBabylonPubKey,
		ValidatorBtcPrivKey:       delegatarPrivKey,
		ValidatorBtcKey:           delegatarPrivKey.PubKey(),
		JuryPrivKey:               juryPrivKey,
		JuryKey:                   juryPrivKey.PubKey(),
		StakingTime:               stakingTime,
		StakingAmount:             stakingAmount,
		Script:                    script,
	}
}

func initBtcWalletClient(
	t *testing.T,
	client walletcontroller.WalletController,
	walletPrivKey *btcec.PrivateKey,
	outputsToWaitFor int) {

	err := ImportWalletSpendingKey(t, client, walletPrivKey)
	require.NoError(t, err)

	waitForNOutputs(t, client, outputsToWaitFor)
}

func StartManager(
	t *testing.T,
	numMatureOutputsInWallet uint32,
	numbersOfOutputsToWaitForDurintInit int,
	handlers *rpcclient.NotificationHandlers) *TestManager {
	args := []string{
		"--rejectnonstd",
		"--txindex",
		"--trickleinterval=100ms",
		"--debuglevel=debug",
		"--nowinservice",
		// The miner will get banned and disconnected from the node if
		// its requested data are not found. We add a nobanning flag to
		// make sure they stay connected if it happens.
		"--nobanning",
		// Don't disconnect if a reply takes too long.
		"--nostalldetect",
	}

	miner, err := rpctest.New(simnetParams, handlers, args, "")
	require.NoError(t, err)

	privkey, addr, err := GetSpendingKeyAndAddress(uint32(numTestInstances))
	require.NoError(t, err)

	if err := miner.SetUp(true, numMatureOutputsInWallet); err != nil {
		t.Fatalf("unable to set up mining node: %v", err)
	}

	minerNodeRpcConfig := miner.RPCConfig()
	certFile := minerNodeRpcConfig.Certificates

	currentDir, err := os.Getwd()
	require.NoError(t, err)
	walletPath := filepath.Join(currentDir, existingWalletFile)

	wh, err := NewWalletHandler(certFile, walletPath, minerNodeRpcConfig.Host)
	require.NoError(t, err)

	err = wh.Start()
	require.NoError(t, err)

	bh, err := NewBabylonNodeHandler()
	require.NoError(t, err)

	err = bh.Start()
	require.NoError(t, err)

	// Wait for wallet to re-index the outputs
	time.Sleep(5 * time.Second)

	cfg := defaultStakerConfig(certFile, minerNodeRpcConfig.Host)

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.Out = os.Stdout

	// babylon configs for sending transactions
	cfg.BabylonConfig.KeyDirectory = bh.GetNodeDataDir()
	// need to use this one to send otherwise we will have account sequence mismatch
	// errors
	cfg.BabylonConfig.Key = "test-spending-key"

	// Big adjustment to make sure we have enough gas in our transactions
	cfg.BabylonConfig.GasAdjustment = 3.0

	dirPath := filepath.Join(os.TempDir(), "stakerd", "e2etest")
	err = os.MkdirAll(dirPath, 0755)
	require.NoError(t, err)
	dbTempDir, err := os.MkdirTemp(dirPath, "db")
	require.NoError(t, err)
	cfg.DBConfig.DBPath = dbTempDir

	dbbackend, err := stakercfg.GetDbBackend(cfg.DBConfig)
	require.NoError(t, err)

	stakerApp, err := staker.NewStakerAppFromConfig(cfg, logger, dbbackend)
	require.NoError(t, err)
	// we require separate client to send BTC headers to babylon node (interface does not need this method?)
	bl, err := babylonclient.NewBabylonController(cfg.BabylonConfig, &cfg.ActiveNetParams, logger)
	require.NoError(t, err)

	initBtcWalletClient(
		t,
		stakerApp.Wallet(),
		privkey,
		numbersOfOutputsToWaitForDurintInit,
	)

	interceptor, err := signal.Intercept()
	require.NoError(t, err)

	addressString := "127.0.0.1:15001"
	addrPort := netip.MustParseAddrPort(addressString)
	address := net.TCPAddrFromAddrPort(addrPort)
	cfg.RpcListeners = append(cfg.RpcListeners, address)

	service := service.NewStakerService(
		cfg,
		stakerApp,
		logger,
		interceptor,
		dbbackend,
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := service.RunUntilShutdown()
		if err != nil {
			t.Fatalf("Error running server: %v", err)
		}
	}()
	// Wait for the server to start
	time.Sleep(3 * time.Second)

	stakerClient, err := dc.NewStakerServiceJsonRpcClient("tcp://" + addressString)
	require.NoError(t, err)

	numTestInstances++

	return &TestManager{
		MinerNode:        miner,
		BtcWalletHandler: wh,
		BabylonHandler:   bh,
		Config:           cfg,
		Db:               dbbackend,
		Sa:               stakerApp,
		BabylonClient:    bl,
		WalletPrivKey:    privkey,
		MinerAddr:        addr,
		serverStopper:    &interceptor,
		wg:               &wg,
		serviceAddress:   addressString,
		StakerClient:     stakerClient,
	}
}

func (tm *TestManager) Stop(t *testing.T) {
	err := tm.BtcWalletHandler.Stop()
	require.NoError(t, err)
	tm.serverStopper.RequestShutdown()
	tm.wg.Wait()
	err = tm.BabylonHandler.Stop()
	require.NoError(t, err)
	err = os.RemoveAll(tm.Config.DBConfig.DBPath)
	require.NoError(t, err)
	err = tm.MinerNode.TearDown()
	require.NoError(t, err)
}

func (tm *TestManager) RestartApp(t *testing.T) {
	// First stop the app
	tm.serverStopper.RequestShutdown()
	tm.wg.Wait()

	// Now reset all components and start again
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.Out = os.Stdout

	dbbackend, err := stakercfg.GetDbBackend(tm.Config.DBConfig)
	require.NoError(t, err)

	stakerApp, err := staker.NewStakerAppFromConfig(tm.Config, logger, dbbackend)
	require.NoError(t, err)

	interceptor, err := signal.Intercept()
	require.NoError(t, err)

	service := service.NewStakerService(
		tm.Config,
		stakerApp,
		logger,
		interceptor,
		dbbackend,
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := service.RunUntilShutdown()
		if err != nil {
			t.Fatalf("Error running server: %v", err)
		}
	}()
	// Wait for the server to start
	time.Sleep(3 * time.Second)

	tm.serverStopper = &interceptor
	tm.wg = &wg
	tm.Db = dbbackend
	tm.Sa = stakerApp
	stakerClient, err := dc.NewStakerServiceJsonRpcClient("tcp://" + tm.serviceAddress)
	require.NoError(t, err)
	tm.StakerClient = stakerClient
}

func ImportWalletSpendingKey(
	t *testing.T,
	walletClient walletcontroller.WalletController,
	privKey *btcec.PrivateKey) error {

	wifKey, err := btcutil.NewWIF(privKey, simnetParams, true)
	require.NoError(t, err)

	err = walletClient.UnlockWallet(int64(3))

	if err != nil {
		return err
	}

	err = walletClient.ImportPrivKey(wifKey)

	if err != nil {
		return err
	}

	return nil
}

// MineBlocksWithTxes mines a single block to include the specifies
// transactions only.
func mineBlockWithTxs(t *testing.T, h *rpctest.Harness, txes []*btcutil.Tx) *wire.MsgBlock {
	var emptyTime time.Time

	// Generate a block.
	b, err := h.GenerateAndSubmitBlock(txes, -1, emptyTime)
	require.NoError(t, err, "unable to mine block")

	block, err := h.Client.GetBlock(b.Hash())
	require.NoError(t, err, "unable to get block")

	return block
}

func retrieveTransactionFromMempool(t *testing.T, h *rpctest.Harness, hashes []*chainhash.Hash) []*btcutil.Tx {
	var txes []*btcutil.Tx
	for _, txHash := range hashes {
		tx, err := h.Client.GetRawTransaction(txHash)
		require.NoError(t, err)
		txes = append(txes, tx)
	}
	return txes
}

func waitForNOutputs(t *testing.T, walletClient walletcontroller.WalletController, n int) {
	require.Eventually(t, func() bool {
		outputs, err := walletClient.ListOutputs(false)

		if err != nil {
			return false
		}

		return len(outputs) >= n
	}, eventuallyWaitTimeOut, eventuallyPollTime)
}

func GetAllMinedBtcHeadersSinceGenesis(t *testing.T, h *rpctest.Harness) []*wire.BlockHeader {
	_, height, err := h.Client.GetBestBlock()
	require.NoError(t, err)

	var headers []*wire.BlockHeader

	for i := 1; i <= int(height); i++ {
		hash, err := h.Client.GetBlockHash(int64(i))
		require.NoError(t, err)
		header, err := h.Client.GetBlockHeader(hash)
		require.NoError(t, err)
		headers = append(headers, header)
	}

	return headers
}

func (tm *TestManager) createAndRegisterValidator(t *testing.T, testStakingData *testStakingData) {
	resp, err := tm.BabylonClient.QueryValidators(100, 0)
	require.NoError(t, err)
	// No validators yet
	require.Len(t, resp.Validators, 0)
	valResp, err := tm.BabylonClient.QueryValidator(testStakingData.ValidatorBtcKey)
	require.Nil(t, valResp)
	require.Error(t, err)
	require.True(t, errors.Is(err, babylonclient.ErrValidatorDoesNotExist))

	pop, err := btcstypes.NewPoP(testStakingData.ValidatorBabylonPrivKey, testStakingData.ValidatorBtcPrivKey)
	require.NoError(t, err)

	btcValKey := bbntypes.NewBIP340PubKeyFromBTCPK(testStakingData.ValidatorBtcKey)

	params, err := tm.BabylonClient.StakingParams()
	require.NoError(t, err)

	_, err = tm.BabylonClient.RegisterValidator(
		testStakingData.ValidatorBabylonPublicKey,
		btcValKey,
		&params.Params.MinCommissionRate,
		&sttypes.Description{},
		pop,
	)

	resp, err = tm.BabylonClient.QueryValidators(100, 0)
	require.NoError(t, err)
	// After registration we should have one validator
	require.Len(t, resp.Validators, 1)
}

func (tm *TestManager) sendHeadersToBabylon(t *testing.T, headers []*wire.BlockHeader) {
	_, err := tm.BabylonClient.InsertBtcBlockHeaders(headers)
	require.NoError(t, err)
}

func (tm *TestManager) mineNEmptyBlocks(t *testing.T, numHeaders uint32, sendToBabylon bool) []*wire.BlockHeader {

	var minedHeaders []*wire.BlockHeader
	for i := 0; i < int(numHeaders); i++ {
		bl := mineBlockWithTxs(t, tm.MinerNode, retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{}))
		minedHeaders = append(minedHeaders, &bl.Header)
	}

	if sendToBabylon {
		tm.sendHeadersToBabylon(t, minedHeaders)
	}

	return minedHeaders
}

func (tm *TestManager) sendStakingTx(t *testing.T, testStakingData *testStakingData) *chainhash.Hash {
	validatorKey := hex.EncodeToString(schnorr.SerializePubKey(testStakingData.ValidatorBtcKey))
	res, err := tm.StakerClient.Stake(
		context.Background(),
		tm.MinerAddr.String(),
		testStakingData.StakingAmount,
		validatorKey,
		int64(testStakingData.StakingTime),
	)
	require.NoError(t, err)
	txHash := res.TxHash

	stakingDetails, err := tm.StakerClient.StakingDetails(context.Background(), txHash)
	require.NoError(t, err)
	require.Equal(t, stakingDetails.StakingTxHash, txHash)
	require.Equal(t, stakingDetails.StakingState, proto.TransactionState_SENT_TO_BTC.String())

	hashFromString, err := chainhash.NewHashFromStr(txHash)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{hashFromString})
		return len(txFromMempool) == 1
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	mBlock := mineBlockWithTxs(t, tm.MinerNode, retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{hashFromString}))
	require.Equal(t, 2, len(mBlock.Transactions))

	_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&mBlock.Header})
	require.NoError(t, err)

	return hashFromString
}

func (tm *TestManager) sendWatchedStakingTx(
	t *testing.T,
	testStakingData *testStakingData,
	params *babylonclient.StakingParams,
) *chainhash.Hash {
	stakingOutput, script, err := staking.BuildStakingOutput(
		testStakingData.StakerKey,
		testStakingData.ValidatorBtcKey,
		&params.JuryPk,
		testStakingData.StakingTime,
		btcutil.Amount(testStakingData.StakingAmount),
		simnetParams,
	)

	require.NoError(t, err)

	err = tm.Sa.Wallet().UnlockWallet(20)
	require.NoError(t, err)

	tx, err := tm.Sa.Wallet().CreateAndSignTx(
		[]*wire.TxOut{stakingOutput},
		2000,
		tm.MinerAddr,
	)
	require.NoError(t, err)
	txHash := tx.TxHash()

	_, err = tm.Sa.Wallet().SendRawTransaction(tx, true)
	require.NoError(t, err)

	stakingOutputIdx, err := staking.GetIdxOutputCommitingToScript(
		tx, script, simnetParams,
	)

	require.NoError(t, err)

	slashingTx, err := staking.BuildSlashingTxFromStakingTxStrict(
		tx,
		uint32(stakingOutputIdx),
		params.SlashingAddress,
		int64(params.MinSlashingTxFeeSat)+10,
		script,
		simnetParams,
	)

	require.NoError(t, err)

	slashSig, err := staking.SignTxWithOneScriptSpendInputFromScript(
		slashingTx,
		tx.TxOut[stakingOutputIdx],
		tm.WalletPrivKey,
		script,
	)

	require.NoError(t, err)

	serializedStakingTx, err := utils.SerializeBtcTransaction(tx)
	require.NoError(t, err)
	serializedSlashingTx, err := utils.SerializeBtcTransaction(slashingTx)
	require.NoError(t, err)

	// TODO: Update pop when new version will be ready
	pop, err := btcstypes.NewPoP(
		testStakingData.StakerBabylonPrivKey,
		tm.WalletPrivKey,
	)

	require.NoError(t, err)

	_, err = tm.StakerClient.WatchStaking(
		context.Background(),
		hex.EncodeToString(serializedStakingTx),
		hex.EncodeToString(script),
		hex.EncodeToString(serializedSlashingTx),
		hex.EncodeToString(slashSig.Serialize()),
		hex.EncodeToString(testStakingData.StakerBabylonPubKey.Key),
		tm.MinerAddr.String(),
		hex.EncodeToString(pop.BabylonSig),
		pop.BtcSig.ToHexStr(),
	)

	require.NoError(t, err)

	mBlock := mineBlockWithTxs(t, tm.MinerNode, retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{&txHash}))
	require.Equal(t, 2, len(mBlock.Transactions))
	_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&mBlock.Header})
	require.NoError(t, err)

	return &txHash
}

func (tm *TestManager) spendStakingTxWithHash(t *testing.T, stakingTxHash *chainhash.Hash) (*chainhash.Hash, *btcutil.Amount) {
	res, err := tm.StakerClient.SpendStakingTransaction(context.Background(), stakingTxHash.String())
	require.NoError(t, err)
	spendTxHash, err := chainhash.NewHashFromStr(res.TxHash)
	require.NoError(t, err)

	iAmount, err := strconv.ParseInt(res.TxValue, 10, 64)
	require.NoError(t, err)
	spendTxValue := btcutil.Amount(iAmount)

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{spendTxHash})
		return len(txFromMempool) == 1
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	sendTx := retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{spendTxHash})[0]

	// Tx is in mempool
	txDetails, txState, err := tm.Sa.Wallet().TxDetails(spendTxHash, sendTx.MsgTx().TxOut[0].PkScript)
	require.NoError(t, err)
	require.Nil(t, txDetails)
	require.Equal(t, txState, walletcontroller.TxInMemPool)

	// Block with spend is mined
	mBlock1 := mineBlockWithTxs(t, tm.MinerNode, retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{spendTxHash}))
	require.Equal(t, 2, len(mBlock1.Transactions))

	//Tx is in chain
	txDetails, txState, err = tm.Sa.Wallet().TxDetails(spendTxHash, sendTx.MsgTx().TxOut[0].PkScript)
	require.NoError(t, err)
	require.NotNil(t, txDetails)
	require.Equal(t, txState, walletcontroller.TxInChain)

	return spendTxHash, &spendTxValue
}

func (tm *TestManager) waitForStakingTxState(t *testing.T, txHash *chainhash.Hash, expectedState proto.TransactionState) {
	require.Eventually(t, func() bool {
		detailResult, err := tm.StakerClient.StakingDetails(context.Background(), txHash.String())
		if err != nil {
			return false
		}
		return detailResult.StakingState == expectedState.String()
	}, 1*time.Minute, eventuallyPollTime)
}

func (tm *TestManager) walletUnspentsOutputsContainsOutput(t *testing.T, from btcutil.Address, withValue btcutil.Amount) bool {
	unspentOutputs, err := tm.Sa.ListUnspentOutputs()
	require.NoError(t, err)

	var containsOutput bool = false

	for _, output := range unspentOutputs {
		if output.Address == tm.MinerAddr.String() && int64(output.Amount) == int64(withValue) {
			containsOutput = true
		}
	}

	return containsOutput
}

func (tm *TestManager) insertAllMinedBlocksToBabylon(t *testing.T) {
	headers := GetAllMinedBtcHeadersSinceGenesis(t, tm.MinerNode)
	_, err := tm.BabylonClient.InsertBtcBlockHeaders(headers)
	require.NoError(t, err)
}

func TestSendingStakingTransaction(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// need to have at least 300 block on testnet as only then segwit is activated
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	stakingTime := uint16(staker.GetMinStakingTime(params))
	testStakingData := getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime, 10000)

	hashed, err := chainhash.NewHash(datagen.GenRandomByteArray(r, 32))
	require.NoError(t, err)
	scr, err := txscript.PayToTaprootScript(testStakingData.JuryKey)
	require.NoError(t, err)
	_, st, erro := tm.Sa.Wallet().TxDetails(hashed, scr)
	// query for exsisting tx is not an error, proper state should be returned
	require.NoError(t, erro)
	require.Equal(t, st, walletcontroller.TxNotFound)

	tm.createAndRegisterValidator(t, testStakingData)

	txHash := tm.sendStakingTx(t, testStakingData)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)

	// just enough for time lock to expire
	blockForStakingToExpire := uint32(testStakingData.StakingTime) - params.ConfirmationTimeBlocks - 1
	tm.mineNEmptyBlocks(t, blockForStakingToExpire, false)

	_, spendTxValue := tm.spendStakingTxWithHash(t, txHash)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, false)

	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SPENT_ON_BTC)

	require.True(t, tm.walletUnspentsOutputsContainsOutput(t, tm.MinerAddr, *spendTxValue))

	offset := 0
	limit := 10
	transactionsResult, err := tm.StakerClient.ListStakingTransactions(context.Background(), &offset, &limit)
	require.NoError(t, err)
	require.Len(t, transactionsResult.Transactions, 1)
	require.Equal(t, transactionsResult.TotalTransactionCount, "1")
	require.Equal(t, transactionsResult.Transactions[0].StakingTxHash, txHash.String())
}

func TestSendingWatchedStakingTransaction(t *testing.T) {
	// need to have at least 300 block on testnet as only then segwit is activated
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	stakingTime := uint16(staker.GetMinStakingTime(params))
	testStakingData := getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime, 10000)

	tm.createAndRegisterValidator(t, testStakingData)

	txHash := tm.sendWatchedStakingTx(t, testStakingData, params)
	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
}

func TestRestartingTxNotDeepEnough(t *testing.T) {
	// need to have at least 300 block on testnet as only then segwit is activated
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	stakingTime := uint16(staker.GetMinStakingTime(params))
	testStakingData := getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime, 10000)

	tm.createAndRegisterValidator(t, testStakingData)
	txHash := tm.sendStakingTx(t, testStakingData)

	// restart app when tx is not deep enough
	tm.RestartApp(t)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
}

func TestRestartingTxNotOnBabylon(t *testing.T) {
	// need to have at least 300 block on testnet as only then segwit is activated
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	stakingTime := uint16(staker.GetMinStakingTime(params))
	testStakingData := getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime, 10000)

	tm.createAndRegisterValidator(t, testStakingData)
	txHash := tm.sendStakingTx(t, testStakingData)

	// Confirm tx on btc
	minedBlocks := tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, false)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_CONFIRMED_ON_BTC)

	// restart app, tx is confirmed but not delivered to babylon
	tm.RestartApp(t)

	// send headers to babylon, so that we can send delegation tx
	go tm.sendHeadersToBabylon(t, minedBlocks)

	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
}
