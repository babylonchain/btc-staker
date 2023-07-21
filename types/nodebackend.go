package types

import "fmt"

type SupportedNodeBackend int

const (
	BitcoindNodeBackend SupportedNodeBackend = iota
	BtcdNodeBackend
)

func NewNodeBackend(backend string) (SupportedNodeBackend, error) {
	switch backend {
	case "btcd":
		return BtcdNodeBackend, nil
	case "bitcoind":
		return BitcoindNodeBackend, nil
	default:
		return BtcdNodeBackend, fmt.Errorf("invalid node type: %s", backend)
	}
}
