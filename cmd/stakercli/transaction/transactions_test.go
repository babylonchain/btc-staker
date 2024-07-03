package transaction_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	bbn "github.com/babylonchain/babylon/types"
	"github.com/babylonchain/networks/parameters/parser"

	"github.com/babylonchain/babylon/btcstaking"
	"github.com/babylonchain/babylon/testutil/datagen"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"

	cmdadmin "github.com/babylonchain/btc-staker/cmd/stakercli/admin"
	cmddaemon "github.com/babylonchain/btc-staker/cmd/stakercli/daemon"
	"github.com/babylonchain/btc-staker/cmd/stakercli/transaction"
	"github.com/babylonchain/btc-staker/utils"
)

const (
	fpDepositStakingAmount = 5000000 // 0.05BTC
	fpStakingTimeLock      = 52560   // 1 year
	// Point with unknown discrete logarithm defined in: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
	// using it as internal public key effectively disables taproot key spends
	unspendableKeyPath       = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
	unspendableKeyPathSchnor = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)

var (
	defaultParam = parser.VersionedGlobalParams{
		Version:          0,
		ActivationHeight: 100,
		StakingCap:       3000000,
		CapHeight:        0,
		Tag:              "01020304",
		CovenantPks: []string{
			"03ffeaec52a9b407b355ef6967a7ffc15fd6c3fe07de2844d61550475e7a5233e5",
			"03a5c60c2188e833d39d0fa798ab3f69aa12ed3dd2f3bad659effa252782de3c31",
			"0359d3532148a597a2d05c0395bf5f7176044b1cd312f37701a9b4d0aad70bc5a4",
			"0357349e985e742d5131e1e2b227b5170f6350ac2e2feb72254fcc25b3cee21a18",
			"03c8ccb03c379e452f10c81232b41a1ca8b63d0baf8387e57d302c987e5abb8527",
		},
		CovenantQuorum:    3,
		UnbondingTime:     1000,
		UnbondingFee:      1000,
		MaxStakingAmount:  300000,
		MinStakingAmount:  3000,
		MaxStakingTime:    10000,
		MinStakingTime:    100,
		ConfirmationDepth: 10,
	}

	globalParams = parser.GlobalParams{
		Versions: []*parser.VersionedGlobalParams{&defaultParam},
	}

	paramsMarshalled, _ = json.Marshal(globalParams)

	parsedGlobalParams, _ = parser.ParseGlobalParams(&globalParams)
	lastParams            = parsedGlobalParams.Versions[len(parsedGlobalParams.Versions)-1]
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
		require.NotNil(t, stakingTx)
	})
}

func appRunCreatePhase1StakingTxWithParams(r *rand.Rand, t *testing.T, app *cli.App, arguments []string) transaction.CreatePhase1StakingTxResponse {
	args := []string{"stakercli", "transaction", "create-phase1-staking-transaction-with-params"}
	args = append(args, arguments...)
	output := appRunWithOutput(r, t, app, args)

	var data transaction.CreatePhase1StakingTxResponse
	err := json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)

	return data
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

func appRunCheckPhase1StakingTxParams(r *rand.Rand, t *testing.T, app *cli.App, arguments []string) transaction.CheckPhase1StakingTxResponse {
	args := []string{"stakercli", "transaction", "check-phase1-staking-transaction-params"}
	args = append(args, arguments...)
	output := appRunWithOutput(r, t, app, args)

	var data transaction.CheckPhase1StakingTxResponse
	err := json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)

	return data
}

func genRandomPubKey(t *testing.T) *btcec.PublicKey {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	return privKey.PubKey()
}

func genSchnorPubKeyHex(t *testing.T) string {
	btcPub := genRandomPubKey(t)
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

func appRunCreatePhase1UnbondingTx(r *rand.Rand, t *testing.T, app *cli.App, arguments []string) transaction.CreatePhase1UnbondingTxResponse {
	args := []string{"stakercli", "transaction", "create-phase1-unbonding-transaction"}
	args = append(args, arguments...)
	output := appRunWithOutput(r, t, app, args)

	var data transaction.CreatePhase1UnbondingTxResponse
	err := json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)
	return data
}

func randRange(r *rand.Rand, min, max int) int {
	return rand.Intn(max+1-min) + min
}

func createTempFileWithParams(f *testing.F) string {
	file, err := os.CreateTemp("", "tmpParams-*.json")
	require.NoError(f, err)
	defer file.Close()
	_, err = file.Write(paramsMarshalled)
	require.NoError(f, err)
	info, err := file.Stat()
	require.NoError(f, err)
	return filepath.Join(os.TempDir(), info.Name())
}

type StakeParameters struct {
	StakerPk           *btcec.PublicKey
	FinalityProviderPk *btcec.PublicKey
	StakingTime        uint16
	StakingAmount      btcutil.Amount
	InclusionHeight    uint64
}

func createCustomValidStakeParams(
	t *testing.T,
	r *rand.Rand,
	p *parser.GlobalParams,
	net *chaincfg.Params,
) (*StakeParameters, []string) {
	lastParams := p.Versions[len(p.Versions)-1]
	inclusionHeight := lastParams.ActivationHeight + 1

	stakerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	fpKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	stakingTime := randRange(r, int(lastParams.MinStakingTime), int(lastParams.MaxStakingTime))
	stakingAmount := btcutil.Amount(randRange(r, int(lastParams.MinStakingAmount), int(lastParams.MaxStakingAmount)))

	var args []string
	args = append(args, fmt.Sprintf("--staker-pk=%s", hex.EncodeToString(schnorr.SerializePubKey(stakerKey.PubKey()))))
	args = append(args, fmt.Sprintf("--finality-provider-pk=%s", hex.EncodeToString(schnorr.SerializePubKey(fpKey.PubKey()))))
	args = append(args, fmt.Sprintf("--staking-time=%d", stakingTime))
	args = append(args, fmt.Sprintf("--staking-amount=%d", stakingAmount))
	args = append(args, fmt.Sprintf("--tx-inclusion-height=%d", inclusionHeight))
	args = append(args, fmt.Sprintf("--network=%s", net.Name))
	return &StakeParameters{
		StakerPk:           stakerKey.PubKey(),
		FinalityProviderPk: fpKey.PubKey(),
		StakingTime:        uint16(stakingTime),
		StakingAmount:      stakingAmount,
		InclusionHeight:    inclusionHeight,
	}, args
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
	// should pass without opt flags set
	err := app.Run(stakerCliCheckP1StkTx)
	require.NoError(t, err)

	validBtcPk := "b91ea4619bc7b3f93e5015976f52f666ae4eb5c98018a6c8e41424905fa8591f"
	validFpPk := "a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565"
	validStakingTime := 52560
	realStakingAmount := 5000000
	validCheckArgs := append(stakerCliCheckP1StkTx,
		fmt.Sprintf("--staker-pk=%s", validBtcPk),
		fmt.Sprintf("--finality-provider-pk=%s", validFpPk),
		fmt.Sprintf("--staking-time=%d", validStakingTime),
		fmt.Sprintf("--min-staking-amount=%d", realStakingAmount),
		fmt.Sprintf("--max-staking-amount=%d", realStakingAmount),
	)
	err = app.Run(validCheckArgs)
	require.NoError(t, err)

	err = app.Run([]string{
		"stakercli", "transaction", "check-phase1-staking-transaction",
		"--covenant-quorum=1",
		"--covenant-committee-pks=50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
		"--magic-bytes=62627434",
		"--network=signet",
		"--staking-transaction=02000000000101b8eba8646e5fdb240af853d52c37b6159984c34bebb55c6097c4f0d276e536c80000000000fdffffff0344770d000000000016001461e09f8a6e653c6bdec644874dc119be1b60f27a404b4c00000000002251204a4b057a9fa0510ccdce480fdac5a3cd12329993bac2517afb784a64d11fc1b40000000000000000496a4762627434002dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd500247304402203bae17ac05c211e3c849595ef211f9a23ffc6d32d089e53cfaf81b94353f9e0c022063676b789a3fd85842552cd54408a8e92a1d37f51e0f4765ac29ef89ed707b750121032dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f355800000000",
		"--staker-pk=2dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558",
		"--finality-provider-pk=a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565",
		fmt.Sprintf("--staking-time=%d", validStakingTime),
		fmt.Sprintf("--min-staking-amount=%d", realStakingAmount),
	})
	require.NoError(t, err)

	err = app.Run([]string{
		"stakercli", "transaction", "check-phase1-staking-transaction",
		"--covenant-quorum=1",
		"--covenant-committee-pks=50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
		"--magic-bytes=62627434",
		"--network=signet",
		"--staking-transaction=02000000000101b8eba8646e5fdb240af853d52c37b6159984c34bebb55c6097c4f0d276e536c80000000000fdffffff0344770d000000000016001461e09f8a6e653c6bdec644874dc119be1b60f27a404b4c00000000002251204a4b057a9fa0510ccdce480fdac5a3cd12329993bac2517afb784a64d11fc1b40000000000000000496a4762627434002dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd500247304402203bae17ac05c211e3c849595ef211f9a23ffc6d32d089e53cfaf81b94353f9e0c022063676b789a3fd85842552cd54408a8e92a1d37f51e0f4765ac29ef89ed707b750121032dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f355800000000",
		"--staker-pk=2dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558",
		"--finality-provider-pk=a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565",
		"--staking-time=52560", "--min-staking-amount=50000000",
	})
	require.EqualError(t, err, fmt.Errorf("staking amount in tx %d is less than the min-staking-amount in flag 50000000", realStakingAmount).Error())

	err = app.Run([]string{
		"stakercli", "transaction", "check-phase1-staking-transaction",
		"--covenant-quorum=1",
		"--covenant-committee-pks=50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
		"--magic-bytes=62627434",
		"--network=signet",
		"--staking-transaction=02000000000101b8eba8646e5fdb240af853d52c37b6159984c34bebb55c6097c4f0d276e536c80000000000fdffffff0344770d000000000016001461e09f8a6e653c6bdec644874dc119be1b60f27a404b4c00000000002251204a4b057a9fa0510ccdce480fdac5a3cd12329993bac2517afb784a64d11fc1b40000000000000000496a4762627434002dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd500247304402203bae17ac05c211e3c849595ef211f9a23ffc6d32d089e53cfaf81b94353f9e0c022063676b789a3fd85842552cd54408a8e92a1d37f51e0f4765ac29ef89ed707b750121032dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f355800000000",
		"--staker-pk=2dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558",
		"--finality-provider-pk=a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565",
		"--staking-time=52560", "--min-staking-amount=0", "--max-staking-amount=10",
	})
	require.EqualError(t, err, fmt.Errorf("staking amount in tx %d is more than the max-staking-amount in flag 10", realStakingAmount).Error())

	// check if errors are caught in flags --staker-pk, --finality-provider-pk, --staking-time, --min-staking-amount
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

	invalidStakingTime := 50
	invalidStakingTimeArgs := append(stakerCliCheckP1StkTx,
		fmt.Sprintf("--staking-time=%d", invalidStakingTime),
	)
	err = app.Run(invalidStakingTimeArgs)
	require.EqualError(t, err, fmt.Errorf("staking time in tx %d do not match with flag %d", validStakingTime, invalidStakingTime).Error())

	invalidMinStakingAmount := realStakingAmount + 1
	invalidMinStakingAmountArgs := append(stakerCliCheckP1StkTx,
		fmt.Sprintf("--min-staking-amount=%d", invalidMinStakingAmount),
	)
	err = app.Run(invalidMinStakingAmountArgs)
	require.EqualError(t, err, fmt.Errorf("staking amount in tx %d is less than the min-staking-amount in flag %d", realStakingAmount, invalidMinStakingAmount).Error())

	invalidMaxStakingAmount := realStakingAmount - 1
	invalidMaxStakingAmountArgs := append(stakerCliCheckP1StkTx,
		fmt.Sprintf("--max-staking-amount=%d", invalidMaxStakingAmount),
	)
	err = app.Run(invalidMaxStakingAmountArgs)
	require.EqualError(t, err, fmt.Errorf("staking amount in tx %d is more than the max-staking-amount in flag %d", realStakingAmount, invalidMaxStakingAmount).Error())
}

// Property: Every create should end without error for valid params
func FuzzCreatPhase1Tx(f *testing.F) {
	paramsFilePath := createTempFileWithParams(f)

	datagen.AddRandomSeedsToFuzzer(f, 5)
	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))
		app := testApp()

		var args []string
		args = append(args, paramsFilePath)

		_, createArgs := createCustomValidStakeParams(t, r, &globalParams, &chaincfg.RegressionNetParams)

		args = append(args, createArgs...)

		resCreate := appRunCreatePhase1StakingTxWithParams(
			r, t, app, args,
		)
		require.NotNil(t, resCreate)
	})
}

func keyToSchnorrHex(key *btcec.PublicKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(key))
}

func FuzzCheckPhase1Tx(f *testing.F) {
	paramsFilePath := createTempFileWithParams(f)

	datagen.AddRandomSeedsToFuzzer(f, 5)
	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))
		app := testApp()

		stakerParams, _ := createCustomValidStakeParams(t, r, &globalParams, &chaincfg.RegressionNetParams)

		_, tx, err := btcstaking.BuildV0IdentifiableStakingOutputsAndTx(
			lastParams.Tag,
			stakerParams.StakerPk,
			stakerParams.FinalityProviderPk,
			lastParams.CovenantPks,
			lastParams.CovenantQuorum,
			stakerParams.StakingTime,
			stakerParams.StakingAmount,
			&chaincfg.RegressionNetParams,
		)
		require.NoError(t, err)

		fakeInputHash := sha256.Sum256([]byte{0x01})
		tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: fakeInputHash, Index: 0}, nil, nil))

		serializedStakingTx, err := utils.SerializeBtcTransaction(tx)
		require.NoError(t, err)

		checkArgs := []string{
			paramsFilePath,
			fmt.Sprintf("--staking-transaction=%s", hex.EncodeToString(serializedStakingTx)),
			fmt.Sprintf("--network=%s", chaincfg.RegressionNetParams.Name),
		}

		resCheck := appRunCheckPhase1StakingTxParams(
			r, t, app, checkArgs,
		)
		require.NotNil(t, resCheck)
		require.True(t, resCheck.IsValid)
		require.NotNil(t, resCheck.StakingData)
		require.Equal(t, globalParams.Versions[0].Version, uint64(resCheck.StakingData.ParamsVersion))
		require.Equal(t, stakerParams.StakingAmount, btcutil.Amount(resCheck.StakingData.StakingAmount))
		require.Equal(t, stakerParams.StakingTime, uint16(resCheck.StakingData.StakingTimeBlocks))
		require.Equal(t, keyToSchnorrHex(stakerParams.StakerPk), resCheck.StakingData.StakerPublicKeyHex)
		require.Equal(t, keyToSchnorrHex(stakerParams.FinalityProviderPk), resCheck.StakingData.FinalityProviderPublicKeyHex)
	})
}

func FuzzCreateUnbondingTx(f *testing.F) {
	paramsFilePath := createTempFileWithParams(f)

	datagen.AddRandomSeedsToFuzzer(f, 10)
	f.Fuzz(func(t *testing.T, seed int64) {
		r := rand.New(rand.NewSource(seed))

		stakerParams, _ := createCustomValidStakeParams(t, r, &globalParams, &chaincfg.RegressionNetParams)

		_, tx, err := btcstaking.BuildV0IdentifiableStakingOutputsAndTx(
			lastParams.Tag,
			stakerParams.StakerPk,
			stakerParams.FinalityProviderPk,
			lastParams.CovenantPks,
			lastParams.CovenantQuorum,
			stakerParams.StakingTime,
			stakerParams.StakingAmount,
			&chaincfg.RegressionNetParams,
		)
		require.NoError(t, err)

		fakeInputHash := sha256.Sum256([]byte{0x01})
		tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: fakeInputHash, Index: 0}, nil, nil))

		serializedStakingTx, err := utils.SerializeBtcTransaction(tx)
		require.NoError(t, err)

		createTxCmdArgs := []string{
			paramsFilePath,
			fmt.Sprintf("--staking-transaction=%s", hex.EncodeToString(serializedStakingTx)),
			fmt.Sprintf("--tx-inclusion-height=%d", stakerParams.InclusionHeight),
			fmt.Sprintf("--network=%s", chaincfg.RegressionNetParams.Name),
		}

		app := testApp()
		unbondingTxResponse := appRunCreatePhase1UnbondingTx(r, t, app, createTxCmdArgs)
		require.NotNil(t, unbondingTxResponse)
		utx, _, err := bbn.NewBTCTxFromHex(unbondingTxResponse.UnbondingTxHex)
		require.NoError(t, err)
		require.NotNil(t, utx)

		decodedBytes, err := base64.StdEncoding.DecodeString(unbondingTxResponse.UnbondingPsbtPacketBase64)
		require.NoError(t, err)
		require.NotNil(t, decodedBytes)
		decoded, err := psbt.NewFromRawBytes(bytes.NewReader(decodedBytes), false)
		require.NoError(t, err)
		require.NotNil(t, decoded)
	})
}
