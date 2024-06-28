package e2etest

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/babylonchain/babylon/types"
	"github.com/btcsuite/btcd/btcec/v2"
)

type BabylonNode struct {
	cmd        *exec.Cmd
	pidFile    string
	DataDir    string
	WalletName string
}

func newBabylonNode(dataDir, walletName string, cmd *exec.Cmd) *BabylonNode {
	return &BabylonNode{
		DataDir:    dataDir,
		cmd:        cmd,
		WalletName: walletName,
	}
}

func (n *BabylonNode) start() error {
	if err := n.cmd.Start(); err != nil {
		return err
	}

	pid, err := os.Create(filepath.Join(n.DataDir,
		fmt.Sprintf("%s.pid", "config")))
	if err != nil {
		return err
	}

	n.pidFile = pid.Name()
	if _, err = fmt.Fprintf(pid, "%d\n", n.cmd.Process.Pid); err != nil {
		return err
	}

	if err := pid.Close(); err != nil {
		return err
	}

	return nil
}

func (n *BabylonNode) stop() (err error) {
	if n.cmd == nil || n.cmd.Process == nil {
		// return if not properly initialized
		// or error starting the process
		return nil
	}

	defer func() {
		err = n.cmd.Wait()
	}()

	if runtime.GOOS == "windows" {
		return n.cmd.Process.Signal(os.Kill)
	}
	return n.cmd.Process.Signal(os.Interrupt)
}

func (n *BabylonNode) cleanup() error {
	if n.pidFile != "" {
		if err := os.Remove(n.pidFile); err != nil {
			log.Printf("unable to remove file %s: %v", n.pidFile,
				err)
		}
	}

	dirs := []string{
		n.DataDir,
	}
	var err error
	for _, dir := range dirs {
		if err = os.RemoveAll(dir); err != nil {
			log.Printf("Cannot remove dir %s: %v", dir, err)
		}
	}
	return nil
}

func (n *BabylonNode) shutdown() error {
	if err := n.stop(); err != nil {
		return err
	}
	if err := n.cleanup(); err != nil {
		return err
	}
	return nil
}

type BabylonNodeHandler struct {
	BabylonNode *BabylonNode
}

func NewBabylonNodeHandler(
	coventantQUorum int,
	covenantPk1 *btcec.PublicKey,
	covenantPk2 *btcec.PublicKey,
	covenantPk3 *btcec.PublicKey,
	slashingAddress string,
	baseHeaderHex string,
) (*BabylonNodeHandler, error) {
	testDir, err := baseDirBabylondir()
	if err != nil {
		return nil, err
	}

	quorumString := strconv.Itoa(coventantQUorum)
	pubBabylon1 := types.NewBIP340PubKeyFromBTCPK(covenantPk1)
	pubBabylon2 := types.NewBIP340PubKeyFromBTCPK(covenantPk2)
	pubBabylon3 := types.NewBIP340PubKeyFromBTCPK(covenantPk3)

	walletName := "node0"
	initTestnetCmd := exec.Command(
		"babylond",
		"testnet",
		"--v=1",
		fmt.Sprintf("--output-dir=%s", testDir),
		"--starting-ip-address=192.168.10.2",
		"--keyring-backend=test",
		"--chain-id=chain-test",
		"--btc-finalization-timeout=4",
		"--btc-confirmation-depth=2",
		"--btc-network=regtest",
		fmt.Sprintf("--slashing-address=%s", slashingAddress),
		fmt.Sprintf("--btc-base-header=%s", baseHeaderHex),
		"--additional-sender-account",
		fmt.Sprintf("--covenant-quorum=%s", quorumString),
		fmt.Sprintf("--covenant-pks=%s,%s,%s", pubBabylon1.MarshalHex(), pubBabylon2.MarshalHex(), pubBabylon3.MarshalHex()),
	)

	var stderr bytes.Buffer
	initTestnetCmd.Stderr = &stderr

	err = initTestnetCmd.Run()

	if err != nil {
		// remove the testDir if this fails
		_ = os.RemoveAll(testDir)
		fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		return nil, err
	}

	nodeDataDir := filepath.Join(testDir, walletName, "babylond")

	f, err := os.Create(filepath.Join(testDir, "babylon.log"))
	if err != nil {
		return nil, err
	}

	startCmd := exec.Command(
		"babylond",
		"start",
		fmt.Sprintf("--home=%s", nodeDataDir),
		"--log_level=debug",
	)

	startCmd.Stdout = f

	return &BabylonNodeHandler{
		BabylonNode: newBabylonNode(testDir, walletName, startCmd),
	}, nil
}

func (w *BabylonNodeHandler) Start() error {
	if err := w.BabylonNode.start(); err != nil {
		// try to cleanup after start error, but return original error
		_ = w.BabylonNode.cleanup()
		return err
	}
	return nil
}

func (w *BabylonNodeHandler) Stop() error {
	if err := w.BabylonNode.shutdown(); err != nil {
		return err
	}

	return nil
}

func (w *BabylonNodeHandler) GetNodeDataDir() string {
	return w.BabylonNode.GetNodeDataDir()
}

// GetNodeDataDir returns the home path of the babylon node.
func (n *BabylonNode) GetNodeDataDir() string {
	dir := filepath.Join(n.DataDir, n.WalletName, "babylond")
	return dir
}

// TxBankSend send transaction to a address from the node address.
func (n *BabylonNode) TxBankSend(addr, coins string) error {
	flags := []string{
		"tx",
		"bank",
		"send",
		n.WalletName,
		addr, coins,
		"--keyring-backend=test",
		fmt.Sprintf("--home=%s", n.GetNodeDataDir()),
		"--log_level=debug",
		"--chain-id=chain-test",
		"-b=sync", "--yes", "--gas-prices=10ubbn",
	}

	cmd := exec.Command("babylond", flags...)
	_, err := cmd.Output()
	if err != nil {
		return err
	}
	return nil
}

// TxBankMultiSend send transaction to multiple addresses from the node address.
func (n *BabylonNode) TxBankMultiSend(coins string, addresses ...string) error {
	// babylond tx bank multi-send [from_key_or_address] [to_address_1 to_address_2 ...] [amount] [flags]
	switch len(addresses) {
	case 0:
		return nil
	case 1:
		return n.TxBankSend(addresses[0], coins)
	default:
		flags := []string{
			"tx",
			"bank",
			"multi-send",
			n.WalletName,
		}
		flags = append(flags, addresses...)
		flags = append(flags,
			coins,
			"--keyring-backend=test",
			fmt.Sprintf("--home=%s", n.GetNodeDataDir()),
			"--log_level=debug",
			"--chain-id=chain-test",
			"-b=sync", "--yes", "--gas-prices=10ubbn",
		)

		cmd := exec.Command("babylond", flags...)
		_, err := cmd.Output()
		if err != nil {
			return err
		}
		return nil
	}
}

func baseDirBabylondir() (string, error) {
	tempPath := os.TempDir()

	tempName, err := os.MkdirTemp(tempPath, "zBabylonTestStaker")
	if err != nil {
		return "", err
	}

	err = os.Chmod(tempName, 0755)

	if err != nil {
		return "", err
	}

	return tempName, nil
}
