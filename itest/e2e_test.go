//go:build e2e
// +build e2e

package e2etest

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bbntypes "github.com/babylonchain/babylon/types"
	btcstypes "github.com/babylonchain/babylon/x/btcstaking/types"
	secp256k1 "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"

	staking "github.com/babylonchain/babylon/btcstaking"
	"github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/proto"
	"github.com/babylonchain/btc-staker/staker"
	"github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/types"
	"github.com/babylonchain/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/kvdb"
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
}

type testStakingData struct {
	StakerKey                  *btcec.PublicKey
	ValidatorBabaylonPrivKey   *secp256k1.PrivKey
	ValidatorBabaylonPublicKey *secp256k1.PubKey
	ValidatorBtcPrivKey        *btcec.PrivateKey
	ValidatorBtcKey            *btcec.PublicKey
	JuryPrivKey                *btcec.PrivateKey
	JuryKey                    *btcec.PublicKey
	StakingTime                uint16
	StakingAmount              int64
	Script                     []byte
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

	validatorBabaylonPrivKey := secp256k1.GenPrivKey()
	validatorBabaylonPubKey := validatorBabaylonPrivKey.PubKey().(*secp256k1.PubKey)

	return &testStakingData{
		StakerKey:                  stakerKey,
		ValidatorBabaylonPrivKey:   validatorBabaylonPrivKey,
		ValidatorBabaylonPublicKey: validatorBabaylonPubKey,
		ValidatorBtcPrivKey:        delegatarPrivKey,
		ValidatorBtcKey:            delegatarPrivKey.PubKey(),
		JuryPrivKey:                juryPrivKey,
		JuryKey:                    juryPrivKey.PubKey(),
		StakingTime:                stakingTime,
		StakingAmount:              stakingAmount,
		Script:                     script,
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

	err = stakerApp.Start()
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
	}
}

func (tm *TestManager) Stop(t *testing.T) {
	err := tm.BtcWalletHandler.Stop()
	require.NoError(t, err)
	err = tm.Sa.Stop()
	require.NoError(t, err)
	err = tm.BabylonHandler.Stop()
	require.NoError(t, err)
	err = tm.Db.Close()
	require.NoError(t, err)
	err = os.RemoveAll(tm.Config.DBConfig.DBPath)
	require.NoError(t, err)
	err = tm.MinerNode.TearDown()
	require.NoError(t, err)
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

	pop, err := btcstypes.NewPoP(testStakingData.ValidatorBabaylonPrivKey, testStakingData.ValidatorBtcPrivKey)
	require.NoError(t, err)

	btcValKey := bbntypes.NewBIP340PubKeyFromBTCPK(testStakingData.ValidatorBtcKey)

	_, err = tm.BabylonClient.RegisterValidator(
		testStakingData.ValidatorBabaylonPublicKey,
		btcValKey,
		pop,
	)

	resp, err = tm.BabylonClient.QueryValidators(100, 0)
	require.NoError(t, err)
	// After registration we should have one validator
	require.Len(t, resp.Validators, 1)
}

func (tm *TestManager) mineNEmptyBlocks(t *testing.T, numHeaders uint32, sendToBabylon bool) {

	var minedHeaders []*wire.BlockHeader
	for i := 0; i < int(numHeaders); i++ {
		bl := mineBlockWithTxs(t, tm.MinerNode, retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{}))
		minedHeaders = append(minedHeaders, &bl.Header)
	}

	if sendToBabylon {
		_, err := tm.BabylonClient.InsertBtcBlockHeaders(minedHeaders)
		require.NoError(t, err)
	}
}

func (tm *TestManager) sendStakingTx(t *testing.T, testStakingData *testStakingData) *chainhash.Hash {
	txHash, err := tm.Sa.StakeFunds(
		tm.MinerAddr,
		btcutil.Amount(testStakingData.StakingAmount),
		testStakingData.ValidatorBtcKey,
		testStakingData.StakingTime,
	)
	require.NoError(t, err)

	storedTx, err := tm.Sa.GetStoredTransaction(txHash)
	require.NoError(t, err)
	require.Equal(t, proto.TransactionState_SENT_TO_BTC, storedTx.State)
	require.Equal(t, *txHash, storedTx.BtcTx.TxHash())

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{txHash})
		return len(txFromMempool) == 1
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	mBlock := mineBlockWithTxs(t, tm.MinerNode, retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{txHash}))
	require.Equal(t, 2, len(mBlock.Transactions))

	_, err = tm.BabylonClient.InsertBtcBlockHeaders([]*wire.BlockHeader{&mBlock.Header})
	require.NoError(t, err)

	return txHash
}

func (tm *TestManager) spendStakingTxWithHash(t *testing.T, stakingTxHash *chainhash.Hash) (*chainhash.Hash, *btcutil.Amount) {
	spendTxHash, spendTxValue, err := tm.Sa.SpendStakingOutput(stakingTxHash)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		txFromMempool := retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{spendTxHash})
		return len(txFromMempool) == 1
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	// Block with spend is mined
	mBlock1 := mineBlockWithTxs(t, tm.MinerNode, retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{spendTxHash}))
	require.Equal(t, 2, len(mBlock1.Transactions))
	return spendTxHash, spendTxValue
}

func (tm *TestManager) waitForStakingTxState(t *testing.T, txHash *chainhash.Hash, expectedState proto.TransactionState) {
	require.Eventually(t, func() bool {
		storedTx, err := tm.Sa.GetStoredTransaction(txHash)
		if err != nil {
			return false
		}

		return storedTx.State == expectedState
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

func (tm *TestManager) MinimalStakingTime(t *testing.T) uint16 {
	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	return uint16(params.FinalizationTimeoutBlocks + 1)
}

func TestSendingStakingTransaction(t *testing.T) {
	// need to have at least 300 block on testnet as only then segwit is activated
	numMatureOutputs := uint32(200)
	tm := StartManager(t, numMatureOutputs, 2, nil)
	defer tm.Stop(t)
	tm.insertAllMinedBlocksToBabylon(t)

	cl := tm.Sa.BabylonController()
	params, err := cl.Params()
	require.NoError(t, err)
	stakingTime := uint16(params.FinalizationTimeoutBlocks + 1)

	testStakingData := getTestStakingData(t, tm.WalletPrivKey.PubKey(), stakingTime, 10000)

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
}
