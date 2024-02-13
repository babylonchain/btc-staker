package e2etest

import (
	"encoding/json"
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
		_, err := h.GetBlockCount(h.t)
		h.t.Logf("failed to get block count: %v", err)
		return err == nil
	}, startTimeout, 500*time.Millisecond, "bitcoind did not start")

}

func (h *BitcoindTestHandler) GetBlockCount(t *testing.T) (int, error) {
	buff, _, err := h.m.GetBlockCount(t)
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

func (h *BitcoindTestHandler) CreateWallet(t *testing.T, walletName string) *CreateWalletResponse {
	buff, _, err := h.m.CreateWalletCmd(t, walletName)
	require.NoError(t, err)

	var response CreateWalletResponse
	err = json.Unmarshal(buff.Bytes(), &response)
	require.NoError(t, err)

	return &response
}

func (h *BitcoindTestHandler) GenerateBlocks(t *testing.T, count int) *GenerateBlockResponse {
	buff, _, err := h.m.GenerateBlockCmd(t, count)
	require.NoError(t, err)

	var response GenerateBlockResponse
	err = json.Unmarshal(buff.Bytes(), &response)
	require.NoError(t, err)

	return &response
}
