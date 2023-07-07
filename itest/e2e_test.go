//go:build e2e
// +build e2e

package e2etest

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	staking "github.com/babylonchain/babylon/btcstaking"
	"github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/staker"
	"github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/walletcontroller"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
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
	defaultConfig.BtcNodeBackendConfig.BtcdConfig.RPCHost = btcdHost
	defaultConfig.BtcNodeBackendConfig.BtcdConfig.RawRPCCert = hex.EncodeToString(btcdCert)
	defaultConfig.BtcNodeBackendConfig.BtcdConfig.RPCUser = "user"
	defaultConfig.BtcNodeBackendConfig.BtcdConfig.RPCPass = "pass"
	defaultConfig.BtcNodeBackendConfig.ActiveNodeBackend = stakercfg.BtcdNodeBackend

	// configre wallet rpc
	defaultConfig.ChainConfig.Network = "simnet"
	defaultConfig.ActiveNetParams = *simnetParams
	// Config setting necessary to connect btcwallet daemon
	defaultConfig.WalletConfig.WalletPass = "pass"

	defaultConfig.WalletRpcConfig.Host = "127.0.0.1:18554"
	defaultConfig.WalletRpcConfig.User = "user"
	defaultConfig.WalletRpcConfig.Pass = "pass"
	defaultConfig.WalletRpcConfig.DisableTls = true
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
	MinerNode         *rpctest.Harness
	BtcWalletHandler  *WalletHandler
	Config            *stakercfg.Config
	Sa                *staker.StakerApp
	MockBabylonClient *babylonclient.MockBabylonClient
	WalletPrivKey     *btcec.PrivateKey
	MinerAddr         btcutil.Address
}

type testStakingData struct {
	StakerKey        *btcec.PublicKey
	DelegatarPrivKey *btcec.PrivateKey
	DelegatorKey     *btcec.PublicKey
	JuryPrivKey      *btcec.PrivateKey
	JuryKey          *btcec.PublicKey
	StakingTime      uint16
	StakingAmount    int64
	Script           []byte
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

	return &testStakingData{
		StakerKey:        stakerKey,
		DelegatarPrivKey: delegatarPrivKey,
		DelegatorKey:     delegatarPrivKey.PubKey(),
		JuryPrivKey:      juryPrivKey,
		JuryKey:          juryPrivKey.PubKey(),
		StakingTime:      stakingTime,
		StakingAmount:    stakingAmount,
		Script:           script,
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

// TODO this is needed as we still do not have a way to test with real babylon node
func newStakerAppWithMockBabylonClient(
	config *stakercfg.Config,
	logger *logrus.Logger,
) (*staker.StakerApp, *babylonclient.MockBabylonClient, error) {
	walletClient, err := walletcontroller.NewRpcWalletController(config)
	if err != nil {
		return nil, nil, err
	}

	tracker := staker.NewStakingTxTracker()

	cl := babylonclient.GetMockClient()

	if err != nil {
		return nil, nil, err
	}

	nodeNotifier, err := staker.NewNodeBackend(config.BtcNodeBackendConfig, &config.ActiveNetParams)

	if err != nil {
		return nil, nil, err
	}

	staker, err := staker.NewStakerAppFromDeps(
		config,
		logger,
		cl,
		walletClient,
		nodeNotifier,
		tracker,
	)

	if err != nil {
		return nil, nil, err
	}

	return staker, cl, nil
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

	// Wait for wallet to re-index the outputs
	time.Sleep(5 * time.Second)

	cfg := defaultStakerConfig(certFile, minerNodeRpcConfig.Host)

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.Out = os.Stdout

	stakerApp, mockBabylonClient, err := newStakerAppWithMockBabylonClient(cfg, logger)

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
		MinerNode:         miner,
		BtcWalletHandler:  wh,
		Config:            cfg,
		Sa:                stakerApp,
		MockBabylonClient: mockBabylonClient,
		WalletPrivKey:     privkey,
		MinerAddr:         addr,
	}
}

func (tm *TestManager) Stop(t *testing.T) {
	err := tm.BtcWalletHandler.Stop()
	require.NoError(t, err)
	err = tm.Sa.Stop()
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
func mineBlockWithTxes(t *testing.T, h *rpctest.Harness, txes []*btcutil.Tx) *wire.MsgBlock {
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

func TestSendingStakingTransaction(t *testing.T) {
	numMatureOutputs := uint32(5)
	var submittedTransactions []*chainhash.Hash

	// We are setting handler for transaction hitting the mempool, to be sure we will
	// pass transaction to the miner, in the same order as they were submitted by submitter
	handlers := &rpcclient.NotificationHandlers{
		OnTxAccepted: func(hash *chainhash.Hash, amount btcutil.Amount) {
			submittedTransactions = append(submittedTransactions, hash)
		},
	}
	tm := StartManager(t, numMatureOutputs, 2, handlers)
	// this is necessary to receive notifications about new transactions entering mempool
	err := tm.MinerNode.Client.NotifyNewTransactions(false)
	require.NoError(t, err)
	defer tm.Stop(t)

	testStakingData := getTestStakingData(t, tm.WalletPrivKey.PubKey(), 5, 10000)

	txHash, err := tm.Sa.StakeFunds(
		tm.MinerAddr,
		btcutil.Amount(testStakingData.StakingAmount),
		testStakingData.DelegatorKey,
		testStakingData.StakingTime,
	)
	require.NoError(t, err)

	allCurrentDelegations := tm.Sa.GetAllDelegations()

	require.Equal(t, 1, len(allCurrentDelegations))
	require.Equal(t, txHash.String(), allCurrentDelegations[0].StakingTxHash)
	require.Equal(t, staker.SentToBtc, allCurrentDelegations[0].State)

	require.Eventually(t, func() bool {
		return len(submittedTransactions) == 1
	}, eventuallyWaitTimeOut, eventuallyPollTime)

	require.Equal(t, txHash, submittedTransactions[0])

	mBlock := mineBlockWithTxes(t, tm.MinerNode, retrieveTransactionFromMempool(t, tm.MinerNode, submittedTransactions))
	require.Equal(t, 2, len(mBlock.Transactions))

	cl := tm.Sa.BabylonController()

	params, err := cl.Params()
	require.NoError(t, err)

	go func() {
		// mine confirmation time blocks in background
		for i := 0; i < int(params.ComfirmationTimeBlocks); i++ {
			time.Sleep(1 * time.Second)
			mineBlockWithTxes(t, tm.MinerNode, retrieveTransactionFromMempool(t, tm.MinerNode, []*chainhash.Hash{}))
		}
	}()

	// ultimately message will be sent to babylon node
	msgSent := <-tm.MockBabylonClient.SentMessages

	stakingtxHash := msgSent.StakingTxInfo.Key.Hash.ToChainhash()

	// TODO: check more fields
	require.Equal(t, stakingtxHash, submittedTransactions[0])

	allCurrentDelegations = tm.Sa.GetAllDelegations()
	require.Equal(t, 1, len(allCurrentDelegations))
	require.Equal(t, txHash.String(), allCurrentDelegations[0].StakingTxHash)
	require.Equal(t, staker.SentToBabylon, allCurrentDelegations[0].State)
}
