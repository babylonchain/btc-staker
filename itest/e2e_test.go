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
	"strconv"
	"sync"
	"testing"
	"time"

	staking "github.com/babylonchain/babylon/btcstaking"
	asig "github.com/babylonchain/babylon/crypto/schnorr-adaptor-signature"
	"github.com/babylonchain/babylon/testutil/datagen"
	bbntypes "github.com/babylonchain/babylon/types"
	btcstypes "github.com/babylonchain/babylon/x/btcstaking/types"
	"github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/proto"
	"github.com/babylonchain/btc-staker/staker"
	"github.com/babylonchain/btc-staker/stakercfg"
	service "github.com/babylonchain/btc-staker/stakerservice"
	dc "github.com/babylonchain/btc-staker/stakerservice/client"
	"github.com/babylonchain/btc-staker/types"
	"github.com/babylonchain/btc-staker/utils"
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
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sttypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/lightningnetwork/lnd/signal"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// bitcoin params used for testing
var (
	r = rand.New(rand.NewSource(time.Now().Unix()))

	simnetParams     = &chaincfg.SimNetParams
	submitterAddrStr = "bbn1eppc73j56382wjn6nnq3quu5eye4pmm087xfdh"
	babylonTag       = []byte{1, 2, 3, 4}
	babylonTagHex    = hex.EncodeToString(babylonTag)

	slashingTxChangeAddress, _ = datagen.GenRandomBTCAddress(r, simnetParams)

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
	eventuallyPollTime    = 250 * time.Millisecond
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
	defaultConfig.BtcNodeBackendConfig.FeeMode = "dynamic"
	defaultConfig.BtcNodeBackendConfig.EstimationMode = types.DynamicFeeEstimation
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
	defaultConfig.StakerConfig.BabylonStallingInterval = 1 * time.Second
	defaultConfig.StakerConfig.UnbondingTxCheckInterval = 1 * time.Second

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
	CovenantPrivKeys []*btcec.PrivateKey
}

type testStakingData struct {
	StakerKey                        *btcec.PublicKey
	StakerBabylonPrivKey             *secp256k1.PrivKey
	StakerBabylonPubKey              *secp256k1.PubKey
	FinalityProviderBabylonPrivKey   *secp256k1.PrivKey
	FinalityProviderBabylonPublicKey *secp256k1.PubKey
	FinalityProviderBtcPrivKey       *btcec.PrivateKey
	FinalityProviderBtcKey           *btcec.PublicKey
	SlashingTxChangeAddress          btcutil.Address
	StakingTime                      uint16
	StakingAmount                    int64
}

func (tm *TestManager) getTestStakingData(
	t *testing.T,
	stakerKey *btcec.PublicKey,
	stakingTime uint16,
	stakingAmount int64) *testStakingData {
	delegatarPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	finalityProviderBabylonPrivKey := secp256k1.GenPrivKey()
	finalityProviderBabylonPubKey := finalityProviderBabylonPrivKey.PubKey().(*secp256k1.PubKey)

	stakerBabylonPrivKey := secp256k1.GenPrivKey()
	stakerBabylonPubKey := stakerBabylonPrivKey.PubKey().(*secp256k1.PubKey)

	return &testStakingData{
		StakerKey:                        stakerKey,
		StakerBabylonPrivKey:             stakerBabylonPrivKey,
		StakerBabylonPubKey:              stakerBabylonPubKey,
		FinalityProviderBabylonPrivKey:   finalityProviderBabylonPrivKey,
		FinalityProviderBabylonPublicKey: finalityProviderBabylonPubKey,
		FinalityProviderBtcPrivKey:       delegatarPrivKey,
		FinalityProviderBtcKey:           delegatarPrivKey.PubKey(),
		SlashingTxChangeAddress:          slashingTxChangeAddress,
		StakingTime:                      stakingTime,
		StakingAmount:                    stakingAmount,
	}
}

func (td *testStakingData) withStakingTime(time uint16) *testStakingData {
	tdCopy := *td
	tdCopy.StakingTime = time
	return &tdCopy
}

func (td *testStakingData) withStakingAmout(amout int64) *testStakingData {
	tdCopy := *td
	tdCopy.StakingAmount = int64(amout)
	return &tdCopy
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

	quorum := 2
	numCovenants := 3
	var coventantPrivKeys []*btcec.PrivateKey
	for i := 0; i < numCovenants; i++ {
		covenantPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		coventantPrivKeys = append(coventantPrivKeys, covenantPrivKey)
	}

	bh, err := NewBabylonNodeHandler(
		quorum,
		coventantPrivKeys[0].PubKey(),
		coventantPrivKeys[1].PubKey(),
		coventantPrivKeys[2].PubKey(),
	)
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

	stakerApp, err := staker.NewStakerAppFromConfig(cfg, logger, zapLogger, dbbackend)
	require.NoError(t, err)
	// we require separate client to send BTC headers to babylon node (interface does not need this method?)
	bl, err := babylonclient.NewBabylonController(cfg.BabylonConfig, &cfg.ActiveNetParams, logger, zapLogger)
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
		CovenantPrivKeys: coventantPrivKeys,
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

	stakerApp, err := staker.NewStakerAppFromConfig(tm.Config, logger, zapLogger, dbbackend)
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

func (tm *TestManager) createAndRegisterFinalityProvider(t *testing.T, testStakingData *testStakingData) {
	resp, err := tm.BabylonClient.QueryFinalityProviders(100, 0)
	require.NoError(t, err)
	// No providers yet
	require.Len(t, resp.FinalityProviders, 0)
	valResp, err := tm.BabylonClient.QueryFinalityProvider(testStakingData.FinalityProviderBtcKey)
	require.Nil(t, valResp)
	require.Error(t, err)
	require.True(t, errors.Is(err, babylonclient.ErrFinalityProviderDoesNotExist))

	pop, err := btcstypes.NewPoP(testStakingData.FinalityProviderBabylonPrivKey, testStakingData.FinalityProviderBtcPrivKey)
	require.NoError(t, err)

	btcValKey := bbntypes.NewBIP340PubKeyFromBTCPK(testStakingData.FinalityProviderBtcKey)

	params, err := tm.BabylonClient.QueryStakingTracker()
	require.NoError(t, err)

	_, err = tm.BabylonClient.RegisterFinalityProvider(
		testStakingData.FinalityProviderBabylonPublicKey,
		btcValKey,
		&params.MinComissionRate,
		&sttypes.Description{
			Moniker: "tester",
		},
		pop,
	)

	resp, err = tm.BabylonClient.QueryFinalityProviders(100, 0)
	require.NoError(t, err)
	// After registration we should have one finality provider
	require.Len(t, resp.FinalityProviders, 1)
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
	fpKey := hex.EncodeToString(schnorr.SerializePubKey(testStakingData.FinalityProviderBtcKey))
	res, err := tm.StakerClient.Stake(
		context.Background(),
		tm.MinerAddr.String(),
		testStakingData.SlashingTxChangeAddress.String(),
		testStakingData.StakingAmount,
		[]string{fpKey},
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

func (tm *TestManager) sendMultipleStakingTx(t *testing.T, testStakingData []*testStakingData) []*chainhash.Hash {
	var hashes []*chainhash.Hash
	for _, data := range testStakingData {
		fpKey := hex.EncodeToString(schnorr.SerializePubKey(data.FinalityProviderBtcKey))
		res, err := tm.StakerClient.Stake(
			context.Background(),
			tm.MinerAddr.String(),
			data.SlashingTxChangeAddress.String(),
			data.StakingAmount,
			[]string{fpKey},
			int64(data.StakingTime),
		)
		require.NoError(t, err)
		txHash, err := chainhash.NewHashFromStr(res.TxHash)
		require.NoError(t, err)
		hashes = append(hashes, txHash)
	}

	for _, txHash := range hashes {
		txHash := txHash
		hashStr := txHash.String()
		stakingDetails, err := tm.StakerClient.StakingDetails(context.Background(), hashStr)
		require.NoError(t, err)
		require.Equal(t, stakingDetails.StakingTxHash, hashStr)
		require.Equal(t, stakingDetails.StakingState, proto.TransactionState_SENT_TO_BTC.String())
	}

	mBlock := mineBlockWithTxs(t, tm.MinerNode, retrieveTransactionFromMempool(t, tm.MinerNode, hashes))
	require.Equal(t, len(hashes)+1, len(mBlock.Transactions))

	_, err := tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&mBlock.Header})
	require.NoError(t, err)
	return hashes
}

func (tm *TestManager) sendWatchedStakingTx(
	t *testing.T,
	testStakingData *testStakingData,
	params *babylonclient.StakingParams,
) *chainhash.Hash {
	stakingInfo, err := staking.BuildStakingInfo(
		testStakingData.StakerKey,
		[]*btcec.PublicKey{testStakingData.FinalityProviderBtcKey},
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		testStakingData.StakingTime,
		btcutil.Amount(testStakingData.StakingAmount),
		simnetParams,
	)

	require.NoError(t, err)

	err = tm.Sa.Wallet().UnlockWallet(20)
	require.NoError(t, err)

	tx, err := tm.Sa.Wallet().CreateAndSignTx(
		[]*wire.TxOut{stakingInfo.StakingOutput},
		2000,
		tm.MinerAddr,
	)
	require.NoError(t, err)
	txHash := tx.TxHash()
	_, err = tm.Sa.Wallet().SendRawTransaction(tx, true)
	require.NoError(t, err)

	// Wait for tx to be in mempool
	require.Eventually(t, func() bool {
		tx, err := tm.MinerNode.Client.GetRawTransaction(&txHash)
		if err != nil {
			return false
		}

		if tx == nil {
			return false
		}

		return true
	}, 1*time.Minute, eventuallyPollTime)

	stakingOutputIdx := 0

	require.NoError(t, err)

	slashingTx, err := staking.BuildSlashingTxFromStakingTxStrict(
		tx,
		uint32(stakingOutputIdx),
		params.SlashingAddress, testStakingData.SlashingTxChangeAddress,
		int64(params.MinSlashingTxFeeSat)+10,
		params.SlashingRate,
		simnetParams,
	)
	require.NoError(t, err)

	stakingTxSlashingPathInfo, err := stakingInfo.SlashingPathSpendInfo()

	require.NoError(t, err)

	slashSig, err := staking.SignTxWithOneScriptSpendInputFromScript(
		slashingTx,
		tx.TxOut[stakingOutputIdx],
		tm.WalletPrivKey,
		stakingTxSlashingPathInfo.RevealedLeaf.Script,
	)

	require.NoError(t, err)

	serializedStakingTx, err := utils.SerializeBtcTransaction(tx)
	require.NoError(t, err)
	serializedSlashingTx, err := utils.SerializeBtcTransaction(slashingTx)
	require.NoError(t, err)
	// Build unbonding related data
	unbondingFee := btcutil.Amount(1000)
	unbondingAmount := btcutil.Amount(testStakingData.StakingAmount) - unbondingFee
	unbondingTme := uint16(params.FinalizationTimeoutBlocks) + 1

	unbondingInfo, err := staking.BuildUnbondingInfo(
		testStakingData.StakerKey,
		[]*btcec.PublicKey{testStakingData.FinalityProviderBtcKey},
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		unbondingTme,
		unbondingAmount,
		simnetParams,
	)
	require.NoError(t, err)

	unbondingSlashingPathInfo, err := unbondingInfo.SlashingPathSpendInfo()
	require.NoError(t, err)

	unbondingTx := wire.NewMsgTx(2)
	unbondingTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&txHash, uint32(stakingOutputIdx)), nil, nil))
	unbondingTx.AddTxOut(unbondingInfo.UnbondingOutput)

	slashUnbondingTx, err := staking.BuildSlashingTxFromStakingTxStrict(
		unbondingTx,
		0,
		params.SlashingAddress, testStakingData.SlashingTxChangeAddress,
		int64(params.MinSlashingTxFeeSat)+10,
		params.SlashingRate,
		simnetParams,
	)
	require.NoError(t, err)

	slashUnbondingSig, err := staking.SignTxWithOneScriptSpendInputFromScript(
		slashUnbondingTx,
		unbondingTx.TxOut[0],
		tm.WalletPrivKey,
		unbondingSlashingPathInfo.RevealedLeaf.Script,
	)

	serializedUnbondingTx, err := utils.SerializeBtcTransaction(unbondingTx)
	require.NoError(t, err)
	serializedSlashUnbondingTx, err := utils.SerializeBtcTransaction(slashUnbondingTx)
	require.NoError(t, err)

	// TODO: Update pop when new version will be ready, for now using schnorr as we don't have
	// easy way to generate bip322 sig on backend side
	pop, err := btcstypes.NewPoP(
		testStakingData.StakerBabylonPrivKey,
		tm.WalletPrivKey,
	)
	require.NoError(t, err)

	_, err = tm.StakerClient.WatchStaking(
		context.Background(),
		hex.EncodeToString(serializedStakingTx),
		int(testStakingData.StakingTime),
		int(testStakingData.StakingAmount),
		hex.EncodeToString(schnorr.SerializePubKey(testStakingData.StakerKey)),
		[]string{hex.EncodeToString(schnorr.SerializePubKey(testStakingData.FinalityProviderBtcKey))},
		hex.EncodeToString(serializedSlashingTx),
		hex.EncodeToString(slashSig.Serialize()),
		hex.EncodeToString(testStakingData.StakerBabylonPubKey.Key),
		tm.MinerAddr.String(),
		hex.EncodeToString(pop.BabylonSig),
		hex.EncodeToString(pop.BtcSig),
		hex.EncodeToString(serializedUnbondingTx),
		hex.EncodeToString(serializedSlashUnbondingTx),
		hex.EncodeToString(slashUnbondingSig.Serialize()),
		int(unbondingTme),
		// Use schnor verification
		int(btcstypes.BTCSigType_BIP340),
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

	// Tx is in chain
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

func (tm *TestManager) insertCovenantSigForDelegation(t *testing.T, btcDel *btcstypes.BTCDelegation) {
	slashingTx := btcDel.SlashingTx
	stakingTx := btcDel.StakingTx
	stakingMsgTx, err := bbntypes.NewBTCTxFromBytes(stakingTx)
	require.NoError(t, err)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)

	stakingInfo, err := staking.BuildStakingInfo(
		btcDel.BtcPk.MustToBTCPK(),
		// TODO: Handle multplie providers
		[]*btcec.PublicKey{btcDel.FpBtcPkList[0].MustToBTCPK()},
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		btcDel.GetStakingTime(),
		btcutil.Amount(btcDel.TotalSat),
		simnetParams,
	)
	stakingTxUnbondingPathInfo, err := stakingInfo.UnbondingPathSpendInfo()
	require.NoError(t, err)

	idx, err := bbntypes.GetOutputIdxInBTCTx(stakingMsgTx, stakingInfo.StakingOutput)
	require.NoError(t, err)

	require.NoError(t, err)
	slashingPathInfo, err := stakingInfo.SlashingPathSpendInfo()
	require.NoError(t, err)
	// get covenant private key from the keyring
	valEncKey, err := asig.NewEncryptionKeyFromBTCPK(btcDel.FpBtcPkList[0].MustToBTCPK())
	require.NoError(t, err)

	unbondingMsgTx, err := bbntypes.NewBTCTxFromBytes(btcDel.BtcUndelegation.UnbondingTx)
	require.NoError(t, err)
	unbondingInfo, err := staking.BuildUnbondingInfo(
		btcDel.BtcPk.MustToBTCPK(),
		[]*btcec.PublicKey{btcDel.FpBtcPkList[0].MustToBTCPK()},
		params.CovenantPks,
		params.CovenantQuruomThreshold,
		uint16(btcDel.BtcUndelegation.UnbondingTime),
		btcutil.Amount(unbondingMsgTx.TxOut[0].Value),
		simnetParams,
	)
	require.NoError(t, err)

	// Covenant 0 signatures
	covenantAdaptorStakingSlashing1, err := slashingTx.EncSign(
		stakingMsgTx,
		idx,
		slashingPathInfo.RevealedLeaf.Script,
		tm.CovenantPrivKeys[0],
		valEncKey,
	)
	covenantUnbondingSig1, err := staking.SignTxWithOneScriptSpendInputFromTapLeaf(
		unbondingMsgTx,
		stakingInfo.StakingOutput,
		tm.CovenantPrivKeys[0],
		stakingTxUnbondingPathInfo.RevealedLeaf,
	)
	require.NoError(t, err)
	unbondingSig1 := bbntypes.NewBIP340SignatureFromBTCSig(covenantUnbondingSig1)

	// slashing unbonding tx sig
	unbondingTxSlashingPathInfo, err := unbondingInfo.SlashingPathSpendInfo()
	require.NoError(t, err)
	covenantAdaptorUnbondingSlashing1, err := btcDel.BtcUndelegation.SlashingTx.EncSign(
		unbondingMsgTx,
		0,
		unbondingTxSlashingPathInfo.RevealedLeaf.Script,
		tm.CovenantPrivKeys[0],
		valEncKey,
	)
	require.NoError(t, err)

	_, err = tm.BabylonClient.SubmitCovenantSig(
		bbntypes.NewBIP340PubKeyFromBTCPK(tm.CovenantPrivKeys[0].PubKey()),
		stakingMsgTx.TxHash().String(),
		[][]byte{covenantAdaptorStakingSlashing1.MustMarshal()},
		unbondingSig1,
		[][]byte{covenantAdaptorUnbondingSlashing1.MustMarshal()},
	)
	require.NoError(t, err)

	// Covenant 1 signatures
	covenantAdaptorStakingSlashing2, err := slashingTx.EncSign(
		stakingMsgTx,
		idx,
		slashingPathInfo.RevealedLeaf.Script,
		tm.CovenantPrivKeys[1],
		valEncKey,
	)
	covenantUnbondingSig2, err := staking.SignTxWithOneScriptSpendInputFromTapLeaf(
		unbondingMsgTx,
		stakingInfo.StakingOutput,
		tm.CovenantPrivKeys[1],
		stakingTxUnbondingPathInfo.RevealedLeaf,
	)
	require.NoError(t, err)
	unbondingSig2 := bbntypes.NewBIP340SignatureFromBTCSig(covenantUnbondingSig2)

	// slashing unbonding tx sig

	covenantAdaptorUnbondingSlashing2, err := btcDel.BtcUndelegation.SlashingTx.EncSign(
		unbondingMsgTx,
		0,
		unbondingTxSlashingPathInfo.RevealedLeaf.Script,
		tm.CovenantPrivKeys[1],
		valEncKey,
	)
	require.NoError(t, err)

	require.NoError(t, err)
	_, err = tm.BabylonClient.SubmitCovenantSig(
		bbntypes.NewBIP340PubKeyFromBTCPK(tm.CovenantPrivKeys[1].PubKey()),
		stakingMsgTx.TxHash().String(),
		[][]byte{covenantAdaptorStakingSlashing2.MustMarshal()},
		unbondingSig2,
		[][]byte{covenantAdaptorUnbondingSlashing2.MustMarshal()},
	)
	require.NoError(t, err)
}

func TestStakingFailures(t *testing.T) {
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	stakingTime := uint16(staker.GetMinStakingTime(params))

	testStakingData := tm.getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime, 10000)
	fpKey := hex.EncodeToString(schnorr.SerializePubKey(testStakingData.FinalityProviderBtcKey))

	tm.createAndRegisterFinalityProvider(t, testStakingData)

	// Duplicated provider key
	_, err = tm.StakerClient.Stake(
		context.Background(),
		tm.MinerAddr.String(),
		testStakingData.SlashingTxChangeAddress.String(),
		testStakingData.StakingAmount,
		[]string{fpKey, fpKey},
		int64(testStakingData.StakingTime),
	)
	require.Error(t, err)

	// No provider key
	_, err = tm.StakerClient.Stake(
		context.Background(),
		tm.MinerAddr.String(),
		testStakingData.SlashingTxChangeAddress.String(),
		testStakingData.StakingAmount,
		[]string{},
		int64(testStakingData.StakingTime),
	)
	require.Error(t, err)
}

func TestSendingStakingTransaction(t *testing.T) {
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	stakingTime := uint16(staker.GetMinStakingTime(params))

	testStakingData := tm.getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime, 10000)

	hashed, err := chainhash.NewHash(datagen.GenRandomByteArray(r, 32))
	require.NoError(t, err)
	scr, err := txscript.PayToTaprootScript(tm.CovenantPrivKeys[0].PubKey())
	require.NoError(t, err)
	_, st, erro := tm.Sa.Wallet().TxDetails(hashed, scr)
	// query for exsisting tx is not an error, proper state should be returned
	require.NoError(t, erro)
	require.Equal(t, st, walletcontroller.TxNotFound)

	tm.createAndRegisterFinalityProvider(t, testStakingData)

	txHash := tm.sendStakingTx(t, testStakingData)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)
	// need to activate delegation to unbond
	tm.insertCovenantSigForDelegation(t, pend[0])
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_DELEGATION_ACTIVE)

	// mine one block less than the amount needed to spend staking tx
	blockForStakingToExpire := uint32(testStakingData.StakingTime) - params.ConfirmationTimeBlocks - 2
	tm.mineNEmptyBlocks(t, blockForStakingToExpire, false)

	withdrawableTransactionsResp, err := tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Len(t, withdrawableTransactionsResp.Transactions, 0)
	require.Equal(t, withdrawableTransactionsResp.TotalTransactionCount, "1")
	require.Equal(t, withdrawableTransactionsResp.LastWithdrawableTransactionIndex, "0")

	tm.mineNEmptyBlocks(t, 1, false)

	// need to use eventually as we need to wait for information to flow from node to staker program
	require.Eventually(t, func() bool {
		withdrawableTransactionsResp, err = tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
		require.NoError(t, err)
		return len(withdrawableTransactionsResp.Transactions) > 0
	}, eventuallyWaitTimeOut, eventuallyPollTime)

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

func TestMultipleWithdrawableStakingTransactions(t *testing.T) {
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	minStakingTime := uint16(staker.GetMinStakingTime(params))
	stakingTime1 := minStakingTime
	stakingTime2 := minStakingTime + 4
	stakingTime3 := minStakingTime + 1
	stakingTime4 := minStakingTime + 2
	stakingTime5 := minStakingTime + 3

	testStakingData1 := tm.getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime1, 10000)
	testStakingData2 := testStakingData1.withStakingTime(stakingTime2)
	testStakingData3 := testStakingData1.withStakingTime(stakingTime3)
	testStakingData4 := testStakingData1.withStakingTime(stakingTime4)
	testStakingData5 := testStakingData1.withStakingTime(stakingTime5)

	tm.createAndRegisterFinalityProvider(t, testStakingData1)
	txHashes := tm.sendMultipleStakingTx(t, []*testStakingData{
		testStakingData1,
		testStakingData2,
		testStakingData3,
		testStakingData4,
		testStakingData5,
	})

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)

	for _, txHash := range txHashes {
		txHash := txHash
		tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
	}

	// mine enough block so that:
	// stakingTime1, stakingTime3, stakingTime4 are spendable
	blockForStakingToExpire := uint32(testStakingData4.StakingTime) - params.ConfirmationTimeBlocks - 1
	tm.mineNEmptyBlocks(t, blockForStakingToExpire, false)

	require.Eventually(t, func() bool {
		withdrawableTransactionsResp, err := tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
		require.NoError(t, err)
		return len(withdrawableTransactionsResp.Transactions) == 3
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	withdrawableTransactionsResp, err := tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Len(t, withdrawableTransactionsResp.Transactions, 3)
	require.Equal(t, withdrawableTransactionsResp.LastWithdrawableTransactionIndex, "4")
	// there are total 5 tranascations in database
	require.Equal(t, withdrawableTransactionsResp.TotalTransactionCount, "5")
	// hashes of stakingTime1, stakingTime3, stakingTime4 are spendable
	require.Equal(t, withdrawableTransactionsResp.Transactions[0].StakingTxHash, txHashes[0].String())
	require.Equal(t, withdrawableTransactionsResp.Transactions[1].StakingTxHash, txHashes[2].String())
	require.Equal(t, withdrawableTransactionsResp.Transactions[2].StakingTxHash, txHashes[3].String())

	require.Equal(t, withdrawableTransactionsResp.Transactions[2].TransactionIdx, "4")
}

func TestSendingWatchedStakingTransaction(t *testing.T) {
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	stakingTime := uint16(staker.GetMinStakingTime(params))
	testStakingData := tm.getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime, 10000)

	tm.createAndRegisterFinalityProvider(t, testStakingData)

	txHash := tm.sendWatchedStakingTx(t, testStakingData, params)
	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
}

func TestRestartingTxNotDeepEnough(t *testing.T) {
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	stakingTime := uint16(staker.GetMinStakingTime(params))
	testStakingData := tm.getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime, 10000)

	tm.createAndRegisterFinalityProvider(t, testStakingData)
	txHash := tm.sendStakingTx(t, testStakingData)

	// restart app when tx is not deep enough
	tm.RestartApp(t)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
}

func TestRestartingTxNotOnBabylon(t *testing.T) {
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	stakingTime := uint16(staker.GetMinStakingTime(params))

	testStakingData1 := tm.getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime, 10000)
	testStakingData2 := testStakingData1.withStakingAmout(11000)

	tm.createAndRegisterFinalityProvider(t, testStakingData1)

	txHashes := tm.sendMultipleStakingTx(t, []*testStakingData{
		testStakingData1,
		testStakingData2,
	})

	// Confirm tx on btc
	minedBlocks := tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, false)

	for _, txHash := range txHashes {
		tm.waitForStakingTxState(t, txHash, proto.TransactionState_CONFIRMED_ON_BTC)
	}

	// restart app, tx is confirmed but not delivered to babylon
	tm.RestartApp(t)

	// send headers to babylon, so that we can send delegation tx
	go tm.sendHeadersToBabylon(t, minedBlocks)

	for _, txHash := range txHashes {
		tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
	}
}

func TestStakingUnbonding(t *testing.T) {
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	// large staking time
	stakingTime := uint16(1000)
	testStakingData := tm.getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime, 50000)

	tm.createAndRegisterFinalityProvider(t, testStakingData)

	txHash := tm.sendStakingTx(t, testStakingData)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
	require.NoError(t, err)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)
	// need to activate delegation to unbond
	tm.insertCovenantSigForDelegation(t, pend[0])

	tm.waitForStakingTxState(t, txHash, proto.TransactionState_DELEGATION_ACTIVE)

	feeRate := 2000
	resp, err := tm.StakerClient.UnbondStaking(context.Background(), txHash.String(), &feeRate)
	require.NoError(t, err)

	unbondingTxHash, err := chainhash.NewHashFromStr(resp.UnbondingTxHash)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		tx, err := tm.MinerNode.Client.GetRawTransaction(unbondingTxHash)
		if err != nil {
			return false
		}

		if tx == nil {
			return false

		}

		return true
	}, 1*time.Minute, eventuallyPollTime)
	tx, err := tm.MinerNode.Client.GetRawTransaction(unbondingTxHash)
	require.NoError(t, err)
	block := mineBlockWithTxs(t, tm.MinerNode, []*btcutil.Tx{tx})
	require.Equal(t, 2, len(block.Transactions))
	require.Equal(t, block.Transactions[1].TxHash(), *unbondingTxHash)
	go tm.mineNEmptyBlocks(t, staker.UnbondingTxConfirmations, false)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC)

	withdrawableTransactionsResp, err := tm.StakerClient.WithdrawableTransactions(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Len(t, withdrawableTransactionsResp.Transactions, 1)

	// We can spend unbonding tx immediately as in e2e test, finalization time is 4 blocks and we locked it
	// finalization time + 1 i.e 5 blocks, but to consider unboning tx as confirmed we need to wait for 6 blocks
	// so at this point time lock should already have passed
	tm.spendStakingTxWithHash(t, txHash)
	go tm.mineNEmptyBlocks(t, staker.SpendStakeTxConfirmations, false)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SPENT_ON_BTC)
}

func TestUnbondingRestartWaitingForSignatures(t *testing.T) {
	// need to have at least 300 block on testnet as only then segwit is activated.
	// Mature output is out which has 100 confirmations, which means 200mature outputs
	// will generate 300 blocks
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	// large staking time
	stakingTime := uint16(1000)
	testStakingData := tm.getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime, 50000)

	tm.createAndRegisterFinalityProvider(t, testStakingData)

	txHash := tm.sendStakingTx(t, testStakingData)

	go tm.mineNEmptyBlocks(t, params.ConfirmationTimeBlocks, true)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_SENT_TO_BABYLON)
	require.NoError(t, err)

	// restart app, tx was sent to babylon but we did not receive covenant signatures yet
	tm.RestartApp(t)

	pend, err := tm.BabylonClient.QueryPendingBTCDelegations()
	require.NoError(t, err)
	require.Len(t, pend, 1)
	// need to activate delegation to unbond
	tm.insertCovenantSigForDelegation(t, pend[0])

	tm.waitForStakingTxState(t, txHash, proto.TransactionState_DELEGATION_ACTIVE)

	feeRate := 2000
	unbondResponse, err := tm.StakerClient.UnbondStaking(context.Background(), txHash.String(), &feeRate)
	require.NoError(t, err)
	unbondingTxHash, err := chainhash.NewHashFromStr(unbondResponse.UnbondingTxHash)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		tx, err := tm.MinerNode.Client.GetRawTransaction(unbondingTxHash)
		if err != nil {
			return false
		}

		if tx == nil {
			return false

		}

		return true
	}, 1*time.Minute, eventuallyPollTime)

	// mine tx into the block
	tx, err := tm.MinerNode.Client.GetRawTransaction(unbondingTxHash)
	require.NoError(t, err)
	block := mineBlockWithTxs(t, tm.MinerNode, []*btcutil.Tx{tx})
	require.Equal(t, 2, len(block.Transactions))
	require.Equal(t, block.Transactions[1].TxHash(), *unbondingTxHash)

	go tm.mineNEmptyBlocks(t, staker.UnbondingTxConfirmations, false)
	tm.waitForStakingTxState(t, txHash, proto.TransactionState_UNBONDING_CONFIRMED_ON_BTC)
}
