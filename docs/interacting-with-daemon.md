# Interacting with daemon

Before proceeding, make sure you have installed the required binaries, configured and
started the staker daemon and bitcoin node.

The following guide will show how to stake BTC tokens, withdraw staking rewards and
unbond BTC tokens.

### 1. Stake BTC tokens

#### 1. List active BTC validators on Babylon:

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

```bash
# staker-address is the BTC address obtained from the BTC node 
# connected to staker daemon using list-outputs cmd

# validator-pks is the BTC public key of the validator 
# obtained from babylon-validators cmd

$ stakercli daemon stake \
  --staker-address bcrt1q56ehztys752uzg7fzpear08l5mw8w2kxgz7644 \
  --staking-amount 1000000 \
  --validator-pks 3328782c63404386d9cd905dba5a35975cba629e48192cea4a348937e865d312 \
  --staking-time 100

{
  "tx_hash": "6bf442a2e864172cba73f642ced10c178f6b19097abde41608035fb26a601b10"
}
```

### 2. Withdraw staking rewards:
Withdrawal can only be done after the staking period is over.

```bash
$ stakercli daemon unstake \
--staking-transaction-hash 6bf442a2e864172cba73f642ced10c178f6b19097abde41608035fb26a601b10
```

### 3. Unbond BTC tokens:
Unbonding can be done anytime after staking.
```bash
$ stakercli daemon unbond \
--staking-transaction-hash 6bf442a2e864172cba73f642ced10c178f6b19097abde41608035fb26a601b10
```
