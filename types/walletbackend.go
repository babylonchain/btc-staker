package types

import "fmt"

type SupportedWalletBackend int

const (
	BitcoindWalletBackend SupportedWalletBackend = iota
	BtcwalletWalletBackend
)

func NewWalletBackend(backend string) (SupportedWalletBackend, error) {
	switch backend {
	case "btcwallet":
		return BtcwalletWalletBackend, nil
	case "bitcoind":
		return BitcoindWalletBackend, nil
	default:
		return BtcwalletWalletBackend, fmt.Errorf("invalid wallet type: %s", backend)
	}

}
