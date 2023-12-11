## Prerequisites

1. **Install Binaries:**
   Follow the instructions in
   the [installation section](../../README.md#2-installation) to install the required
   binaries.

2. **Staker Daemon Configuration:**
   Follow the instructions in
   the [Staker Daemon Configuration](stakerd/stakerd-config.md)
   guide to configure the staker daemon.

3. **Start Staker Daemon:**
   Follow the instructions in
   the [Staker Daemon Startup Guide](stakerd/stakerd-startup-guide.md)
   guide to start the staker daemon and connect to a BTC node.

## Interacting with daemon

The following guide will show how to stake BTC tokens, spend staked BTC tokens after
timelock expiration and unbond BTC tokens.

### 1. Stake BTC tokens

#### 1. List active BTC validators on Babylon:

Find the public key of the validator you want to stake to. You can stake to multiple
validators by specifying public keys in the `--validator-pks` flag of the `stake`
command.

```bash
$ stakercli daemon babylon-validators
{
    "validators": [
        {
            "babylon_public_Key": "0294092d0266c8d26544291b692e13f1e4fcba7829c5445ff99fcb3aefb23fe7cd",
            "bitcoin_public_Key": "3328782c63404386d9cd905dba5a35975cba629e48192cea4a348937e865d312"
        }
    ],
    "total_validator_count": "1"
}
```

#### 2. Obtain BTC address from the BTC node that staker daemon is connected to:

Find the BTC address that you want to stake from.

```bash
$ stakercli daemon list-outputs
{
  "outputs": [
    {
      "amount": "10 BTC",
      "address": "bcrt1q56ehztys752uzg7fzpear08l5mw8w2kxgz7644"
    },
    {
      "amount": "10 BTC",
      "address": "bcrt1ql94x9v78ag7qx896f0axka809u55pla8cywsvn"
    }
  ]
}
```

#### 3. Stake BTC tokens:

Stake BTC tokens to the validator(s) of your choice. The `--staking-time` flag
specifies the timelock of the staking transaction in BTC blocks.
The `--staking-amount`
flag specifies the amount of BTC tokens in satoshis to stake.

```bash
$ stakercli daemon stake \
  --staker-address bcrt1q56ehztys752uzg7fzpear08l5mw8w2kxgz7644 \
  --staking-amount 1000000 \
  --validator-pks 3328782c63404386d9cd905dba5a35975cba629e48192cea4a348937e865d312 \
  --staking-time 100

# Transaction details
{
  "tx_hash": "6bf442a2e864172cba73f642ced10c178f6b19097abde41608035fb26a601b10"
}
```

**Note**: You can self delegate i.e. stake to your own validator. Follow
the [validator registration guide](https://github.com/babylonchain/btc-validator/blob/dev/docs/interacting-with-daemons.md#1-creating-a-btc-validator)
to create and register a validator to Babylon. Once the validator is registered, you
can use your validator BTC public key in the `--validator-pks` flag of the `stake`
command.

### 2. Spend staked funds:

Spends staking transaction and sends funds back to staker this can only be done after
timelock of staking transaction expires.

```bash
$ stakercli daemon unstake \
  --staking-transaction-hash 6bf442a2e864172cba73f642ced10c178f6b19097abde41608035fb26a601b10
```

### 3. Unbond BTC tokens:

Initiates the unbonding flow: builds unbonding tx, send to babylon, wait for
signatures, and send unbonding tx to BTC chain.

```bash
$ stakercli daemon unbond \
  --staking-transaction-hash 6bf442a2e864172cba73f642ced10c178f6b19097abde41608035fb26a601b10
```
