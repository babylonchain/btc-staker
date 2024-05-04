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
	cmdtx "github.com/babylonchain/btc-staker/cmd/stakercli/transaction"
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
	app.Commands = append(app.Commands, cmdtx.TransactionCommands...)
	return app
}
