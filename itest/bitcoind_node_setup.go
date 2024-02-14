package e2etest

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/babylonchain/btc-staker/itest/containers"
	"github.com/stretchr/testify/require"
)

var (
	startTimeout = 30 * time.Second
)

type CreateWalletResponse struct {
	Name    string `json:"name"`
	Warning string `json:"warning"`
}

type GenerateBlockResponse struct {
	// address of the recipient of rewards
	Address string `json:"address"`
	// blocks generated
	Blocks []string `json:"blocks"`
}

type BitcoindTestHandler struct {
	t *testing.T
	m *containers.Manager
}

func NewBitcoindHandler(t *testing.T) *BitcoindTestHandler {
	m, err := containers.NewManager()
	require.NoError(t, err)
	return &BitcoindTestHandler{
		t: t,
		m: m,
	}
}

func (h *BitcoindTestHandler) Start() {
	tempPath, err := os.MkdirTemp("", "bitcoind-staker-test-*")
	require.NoError(h.t, err)

	h.t.Cleanup(func() {
		_ = os.RemoveAll(tempPath)
	})

	_, err = h.m.RunBitcoindResource(tempPath)
	require.NoError(h.t, err)

	h.t.Cleanup(func() {
		_ = h.m.ClearResources()
	})

	require.Eventually(h.t, func() bool {
		_, err := h.GetBlockCount()
		h.t.Logf("failed to get block count: %v", err)
		return err == nil
	}, startTimeout, 500*time.Millisecond, "bitcoind did not start")

}

func (h *BitcoindTestHandler) GetBlockCount() (int, error) {
	buff, _, err := h.m.ExecBitcoindCliCmd(h.t, []string{"getblockcount"})
	if err != nil {
		return 0, err
	}

	buffStr := buff.String()

	parsedBuffStr := strings.TrimSuffix(buffStr, "\n")

	num, err := strconv.Atoi(parsedBuffStr)
	if err != nil {
		return 0, err
	}

	return num, nil
}

func (h *BitcoindTestHandler) CreateWallet(walletName string, passphrase string) *CreateWalletResponse {
	buff, _, err := h.m.ExecBitcoindCliCmd(h.t, []string{"createwallet", walletName, "false", "false", passphrase})
	require.NoError(h.t, err)

	var response CreateWalletResponse
	err = json.Unmarshal(buff.Bytes(), &response)
	require.NoError(h.t, err)

	return &response
}

func (h *BitcoindTestHandler) GenerateBlocks(count int) *GenerateBlockResponse {
	buff, _, err := h.m.ExecBitcoindCliCmd(h.t, []string{"-generate", fmt.Sprintf("%d", count)})
	require.NoError(h.t, err)

	var response GenerateBlockResponse
	err = json.Unmarshal(buff.Bytes(), &response)
	require.NoError(h.t, err)

	return &response
}
