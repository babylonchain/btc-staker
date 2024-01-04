package utils

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

func GetBtcNetworkParams(network string) (*chaincfg.Params, error) {
	switch network {
	case "testnet3":
		return &chaincfg.TestNet3Params, nil
	case "mainnet":
		return &chaincfg.MainNetParams, nil
	case "regtest":
		return &chaincfg.RegressionNetParams, nil
	case "simnet":
		return &chaincfg.SimNetParams, nil
	case "signet":
		return &chaincfg.SigNetParams, nil
	default:
		return nil, fmt.Errorf("unknown network %s", network)
	}
}

func SerializeBtcTransaction(tx *wire.MsgTx) ([]byte, error) {
	var txBuf bytes.Buffer
	if err := tx.Serialize(&txBuf); err != nil {
		return nil, err
	}
	return txBuf.Bytes(), nil
}

// push msg to channel c, or quit if quit channel is closed
func PushOrQuit[T any](c chan<- T, msg T, quit <-chan struct{}) {
	select {
	case c <- msg:
	case <-quit:
	}
}

func HandleReqRespOrQuit[T any](r <-chan T, e <-chan error, q <-chan struct{}) (T, error) {
	var noResp T

	select {
	case resp := <-r:
		return resp, nil

	case err := <-e:
		return noResp, err

	case <-q:
		return noResp, fmt.Errorf("quitting")
	}
}

type Requestable[Result any] interface {
	ResultChan() chan Result
	ErrorChan() chan error
}

type Request[A any] struct {
	resultChan chan A
	errChan    chan error
}

func NewRequest[A any]() Request[A] {
	return Request[A]{
		resultChan: make(chan A, 1),
		errChan:    make(chan error, 1),
	}
}

func (r *Request[A]) ResultChan() chan A {
	return r.resultChan
}

func (r *Request[A]) ErrorChan() chan error {
	return r.errChan
}

func SendRequestAndWaitForResponseOrQuit[Result any, Req Requestable[Result]](
	r Req,
	c chan<- Req,
	quit <-chan struct{},
) (Result, error) {
	PushOrQuit[Req](
		c,
		r,
		quit,
	)

	return HandleReqRespOrQuit[Result](
		r.ResultChan(),
		r.ErrorChan(),
		quit,
	)
}
