package main

import (
	"fmt"
	"os"

	bbn "github.com/babylonchain/babylon/types"
	btcstypes "github.com/babylonchain/babylon/x/btcstaking/types"
	cl "github.com/babylonchain/btc-staker/babylonclient"
	scfg "github.com/babylonchain/btc-staker/stakercfg"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/jessevdk/go-flags"
)

// stakerKey := stakerPrivKey.PubKey()

// encodedPubKey := schnorr.SerializePubKey(stakerKey)

// babylonSig, err := app.babylonClient.Sign(
// 	encodedPubKey,
// )

// if err != nil {
// 	return nil, err
// }

// babylonSigHash := tmhash.Sum(babylonSig)

// btcSig, err := schnorr.Sign(stakerPrivKey, babylonSigHash)

// if err != nil {
// 	return nil, err
// }

// pop, err := cl.NewBabylonPop(
// 	cl.SchnorrType,
// 	babylonSig,
// 	btcSig.Serialize(),
// )

func main() {
	cfg, log, zap, err := scfg.LoadConfig()

	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			// Print error if not due to help request.
			err = fmt.Errorf("failed to load config: %w", err)
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Help was requested, exit normally.
		os.Exit(0)
	}

	babylonClient, err := cl.NewBabylonController(cfg.BabylonConfig, &cfg.ActiveNetParams, log, zap)

	if err != nil {
		err = fmt.Errorf("failed to load config: %w", err)
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	bogusStakerBtcKey, err := btcec.NewPrivateKey()

	if err != nil {
		panic(err)
	}

	stakerKey := bogusStakerBtcKey.PubKey()

	encodedPubKey := schnorr.SerializePubKey(stakerKey)

	babylonSig, err := babylonClient.Sign(
		encodedPubKey,
	)

	if err != nil {
		panic(err)
	}

	babylonSigHash := tmhash.Sum(babylonSig)

	btcSig, err := schnorr.Sign(bogusStakerBtcKey, babylonSigHash)

	if err != nil {
		panic(err)
	}

	pop := btcstypes.ProofOfPossession{
		BtcSigType: btcstypes.BTCSigType_BIP340,
		BabylonSig: babylonSig,
		BtcSig:     btcSig.Serialize(),
	}

	err = pop.VerifyBIP340(
		babylonClient.GetPubKey(),
		bbn.NewBIP340PubKeyFromBTCPK(stakerKey),
	)

	if err != nil {
		panic(fmt.Errorf("failed to verify PoP: %w", err))
	}
	fmt.Println("success")
}
