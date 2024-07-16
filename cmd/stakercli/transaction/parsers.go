package transaction

import (
	"encoding/hex"
	"fmt"
	"math"

	"github.com/babylonchain/babylon/btcstaking"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/urfave/cli"
)

func parseSchnorPubKeyFromCliCtx(ctx *cli.Context, flagName string) (*btcec.PublicKey, error) {
	pkHex := ctx.String(flagName)
	return parseSchnorPubKeyFromHex(pkHex)
}

func parseSchnorPubKeyFromHex(pkHex string) (*btcec.PublicKey, error) {
	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil {
		return nil, err
	}

	pk, err := schnorr.ParsePubKey(pkBytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func parseAmountFromCliCtx(ctx *cli.Context, flagName string) (btcutil.Amount, error) {
	amt := ctx.Int64(flagName)

	if amt <= 0 {
		return 0, fmt.Errorf("staking amount should be greater than 0")
	}

	return btcutil.Amount(amt), nil
}

func parseLockTimeBlocksFromCliCtx(ctx *cli.Context, flagName string) (uint16, error) {
	timeBlocks := ctx.Int64(flagName)

	if timeBlocks <= 0 {
		return 0, fmt.Errorf("staking time blocks should be greater than 0")
	}

	if timeBlocks > math.MaxUint16 {
		return 0, fmt.Errorf("staking time blocks should be less or equal to %d", math.MaxUint16)
	}

	return uint16(timeBlocks), nil
}

func parseCovenantKeysFromCliCtx(ctx *cli.Context) ([]*btcec.PublicKey, error) {
	covenantMembersPks := ctx.StringSlice(covenantMembersPksFlag)
	return parseCovenantKeysFromSlice(covenantMembersPks)
}

func parseCovenantKeysFromSlice(covenantMembersPks []string) ([]*btcec.PublicKey, error) {
	covenantPubKeys := make([]*btcec.PublicKey, len(covenantMembersPks))

	for i, fpPk := range covenantMembersPks {
		fpPkBytes, err := hex.DecodeString(fpPk)
		if err != nil {
			return nil, err
		}

		fpSchnorrKey, err := schnorr.ParsePubKey(fpPkBytes)
		if err != nil {
			return nil, err
		}

		covenantPubKeys[i] = fpSchnorrKey
	}

	return covenantPubKeys, nil
}

func parseTagFromCliCtx(ctx *cli.Context) ([]byte, error) {
	tagHex := ctx.String(tagFlag)
	return parseTagFromHex(tagHex)
}

func parseTagFromHex(tagHex string) ([]byte, error) {
	tag, err := hex.DecodeString(tagHex)
	if err != nil {
		return nil, err
	}

	if len(tag) != btcstaking.TagLen {
		return nil, fmt.Errorf("tag should be of length %d", btcstaking.TagLen)
	}

	return tag, nil
}
