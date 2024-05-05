package transaction_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/babylonchain/babylon/btcstaking"
	"github.com/babylonchain/babylon/testutil/datagen"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	cmdadmin "github.com/babylonchain/btc-staker/cmd/stakercli/admin"
	cmddaemon "github.com/babylonchain/btc-staker/cmd/stakercli/daemon"
	"github.com/babylonchain/btc-staker/cmd/stakercli/transaction"
)

const (
	fpDepositStakingAmount = 5000000 // 0.05BTC
	fpStakingTimeLock      = 52560   // 1 year
	// Point with unknown discrete logarithm defined in: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
	// using it as internal public key effectively disables taproot key spends
	unspendableKeyPath       = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
	unspendableKeyPathSchnor = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)

func TestVerifyUnspendableKeyPath(t *testing.T) {
	bz, err := hex.DecodeString(unspendableKeyPath)
	require.NoError(t, err)

	pk, err := btcec.ParsePubKey(bz)
	require.NoError(t, err)

	schnorrBz := schnorr.SerializePubKey(pk)
	require.Equal(t, unspendableKeyPathSchnor, hex.EncodeToString(schnorrBz))
}

func FuzzFinalityProviderDeposit(f *testing.F) {
	datagen.AddRandomSeedsToFuzzer(f, 10)
	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))
		magicBytesHex := datagen.GenRandomHexStr(r, btcstaking.MagicBytesLen)

		commonFlags := []string{
			fmt.Sprintf("--covenant-committee-pks=%s", unspendableKeyPathSchnor),
			fmt.Sprintf("--magic-bytes=%s", magicBytesHex),
			"--covenant-quorum=1", "--network=regtest",
		}

		fpPkHex, btcStakerPkHex := genSchnorPubKeyHex(t), genSchnorPubKeyHex(t)
		createTxCmdArgs := []string{
			fmt.Sprintf("--staker-pk=%s", btcStakerPkHex),
			fmt.Sprintf("--finality-provider-pk=%s", fpPkHex),
			fmt.Sprintf("--staking-amount=%d", fpDepositStakingAmount),
			fmt.Sprintf("--staking-time=%d", fpStakingTimeLock),
		}

		app := testApp()
		stakingTx := appRunCreatePhase1StakingTx(r, t, app, append(createTxCmdArgs, commonFlags...))
		require.NotEmpty(t, stakingTx)

		// TODO: verify how to sign to check tx
		// checkTxCmd := []string{
		// 	"stakercli", "transaction", "check-phase1-staking-transaction",
		// 	fmt.Sprintf("--staking-transaction=%s", stakingTx.StakingTxHex),
		// }

		// appRunWithOutput(r, t, app, append(checkTxCmd, commonFlags...))
	})
}

func appRunCreatePhase1StakingTx(r *rand.Rand, t *testing.T, app *cli.App, arguments []string) transaction.CreatePhase1StakingTxResponse {
	args := []string{"stakercli", "transaction", "create-phase1-staking-transaction"}
	args = append(args, arguments...)
	output := appRunWithOutput(r, t, app, args)

	var data transaction.CreatePhase1StakingTxResponse
	err := json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)

	return data
}

func genSchnorPubKeyHex(t *testing.T) string {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	btcPub := privKey.PubKey()
	return hex.EncodeToString(schnorr.SerializePubKey(btcPub))
}

func appRunWithOutput(r *rand.Rand, t *testing.T, app *cli.App, arguments []string) (output string) {
	outPut := filepath.Join(t.TempDir(), fmt.Sprintf("%s-out.txt", datagen.GenRandomHexStr(r, 10)))
	outPutFile, err := os.Create(outPut)
	require.NoError(t, err)
	defer outPutFile.Close()

	// set file to stdout to read.
	oldStd := os.Stdout
	os.Stdout = outPutFile

	err = app.Run(arguments)
	require.NoError(t, err)

	// set to old stdout
	os.Stdout = oldStd
	return readFromFile(t, outPutFile)
}

func readFromFile(t *testing.T, f *os.File) string {
	_, err := f.Seek(0, 0)
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(f)
	require.NoError(t, err)
	return buf.String()
}

func testApp() *cli.App {
	app := cli.NewApp()
	app.Name = "stakercli"
	app.Commands = append(app.Commands, cmddaemon.DaemonCommands...)
	app.Commands = append(app.Commands, cmdadmin.AdminCommands...)
	app.Commands = append(app.Commands, transaction.TransactionCommands...)
	return app
}

func TestCheckPhase1StakingTransactionCmd(t *testing.T) {
	app := testApp()
	stakerCliCheckP1StkTx := []string{
		"stakercli", "transaction", "check-phase1-staking-transaction",
		"--covenant-quorum=1",
		"--covenant-committee-pks=50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
		"--magic-bytes=01020304",
		"--network=regtest",
		"--staking-transaction=02000000000101ffa5874fdf64a535a4beae47ba0e66278b046baf7b3f3855dbf0413060aaeef90000000000fdffffff03404b4c00000000002251207c2649dc890238fada228d52a4c25fcef82e1cf3d7f53895ca0fcfb15dd142bb0000000000000000496a470102030400b91ea4619bc7b3f93e5015976f52f666ae4eb5c98018a6c8e41424905fa8591fa89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd50c876f7f70d0000001600141b9b57f4d4555e65ceb98c465c9580b0d6b0d0f60247304402200ae05daea3dc62ee7f2720c87705da28077ab19e420538eea5b92718271b4356022026c8367ac8bcd0b6d011842159cd525db672b234789a8d37725b247858c90a120121020721ef511b0faee2a487a346fdb96425d9dd7fa79210adbe7b47f0bcdc7e29de00000000",
	}

	validBtcPk := "b91ea4619bc7b3f93e5015976f52f666ae4eb5c98018a6c8e41424905fa8591f"
	validFpPk := "a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565"
	validCheckArgs := append(stakerCliCheckP1StkTx,
		fmt.Sprintf("--staker-pk=%s", validBtcPk),
		fmt.Sprintf("--finality-provider-pk=%s", validFpPk),
	)
	err := app.Run(validCheckArgs)
	require.NoError(t, err)

	// check if errors caught in flags --staker-pk, --finality-provider-pk
	invalidStakerPk := "badstakerpk"
	invalidBtcStakerArgs := append(stakerCliCheckP1StkTx,
		fmt.Sprintf("--staker-pk=%s", invalidStakerPk),
	)
	err = app.Run(invalidBtcStakerArgs)
	require.EqualError(t, err, fmt.Errorf("staker pk in tx %s do not match with flag %s", validBtcPk, invalidStakerPk).Error())

	invalidFpPk := "badfppk"
	invalidFpPkArgs := append(stakerCliCheckP1StkTx,
		fmt.Sprintf("--finality-provider-pk=%s", invalidFpPk),
	)
	err = app.Run(invalidFpPkArgs)
	require.EqualError(t, err, fmt.Errorf("finality provider pk in tx %s do not match with flag %s", validFpPk, invalidFpPk).Error())

}
