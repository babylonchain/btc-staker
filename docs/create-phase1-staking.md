# Creating and Submitting phase-1 Staking Transactions

The phase-1 staking transaction is a
[Bitcoin Staking transaction](https://github.com/babylonchain/babylon/blob/v0.8.5/docs/staking-script.md)
that includes an additional `OP_RETURN` field containing the staking parameters
to enable for easy identification and taproot decoding through observing the
Bitcoin ledger.

In this document, we will be exploring how to build the phase-1 staking
transaction using a bitcoind wallet, and later funding, signing, and propagating
it to the BTC network.

## Requirements

- [stakercli](../README.md#3-btc-staker-installation)
- [bitcoin-cli](../README.md#21-download-and-extract-bitcoin-binary)
- [jq](https://jqlang.github.io/jq/download/)

The generation of a phase-1 staking transaction does not require
an active `stakerd` daemon that connects to a Babylon node.
It can be generated in offline mode without any external connections.

It only requires the specification of a funding Bitcoin public key. Wallet
creation and generating a Bitcoin address for it are covered by
[this guide (steps 2 to 2.4)](../README.md#2-setting-up-a-bitcoin-node).
You can generate a new address by running the following command
[`bitcoin-cli getnewaddress`](https://chainquery.com/bitcoin-cli/getnewaddress).

```shell
bitcoin-cli -signet \
  -rpcuser=<your_rpc_username> \
  -rpcpassword=<your_rpc_password> \
  -rpcport=38332 \
  -rpcwallet=btc-staker \
  getnewaddress

tb1q9hr5zxsvtzg3gxpewdc7ft9yam2c6cfeaz75jj
```

## Identifying the Staker Public Key

A Bitcoin staking transaction requires the specification
of the staker public key, which corresponds to the public key
of the wallet that is funding the staking transaction.
Once you setup your wallet and an address for it,
you can extract the public key corresponding to it through the
[`bitcoin-cli getaddressinfo`](https://chainquery.com/bitcoin-cli/getaddressinfo).
The output should be a json structure with information about the generated address:

```shell
bitcoin-cli -signet \
  -rpcuser=<your_rpc_username> \
  -rpcpassword=<your_rpc_password> \
  -rpcport=38332 \
  -rpcwallet=btc-staker \
  getaddressinfo tb1q9hr5zxsvtzg3gxpewdc7ft9yam2c6cfeaz75jj

{
  "address": "tb1q9hr5zxsvtzg3gxpewdc7ft9yam2c6cfeaz75jj",
  "scriptPubKey": "00142dc7411a0c58911418397371e4aca4eed58d6139",
  "ismine": true,
  "solvable": true,
  "desc": "wpkh([40009876/0h/0h/0h]032dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558)#rneryczc",
  "iswatchonly": false,
  "isscript": false,
  "iswitness": true,
  "witness_version": 0,
  "witness_program": "2dc7411a0c58911418397371e4aca4eed58d6139",
  "pubkey": "032dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558",
  "ischange": false,
  "timestamp": 1714999109,
  "hdkeypath": "m/0'/0'/0'",
  "hdseedid": "85e1a0d49dfa38c18a8a61ae7b2f2daa366fdcb3",
  "hdmasterfingerprint": "40009876",
  "labels": [
    ""
  ]
}
```

The BTC staker public key as hex can be derived from the `pubkey` property.
You can use the `jq` utility to reduce it as follows:

```shell
bitcoin-cli -signet \
  -rpcuser=<your_rpc_username> \
  -rpcpassword=<your_rpc_password> \
  -rpcport=38332 \
  -rpcwallet=btc-staker \
  getaddressinfo <addr> | jq -r '.pubkey[2:]'

2dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558
```

In this example the value `2dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558`
is the BTC staker public key in hex format. It is the value to be used
in the `--staker-pk` flag of `create-phase1-staking-transaction` command.

## Create Raw Transaction

The binary `stakercli` will be used to generate the transaction using
the `transaction create-phase1-staking-transaction` command.

This command has several flag options:

- `--staker-pk` Schnorr BTC staker public key in hex format.
- `--finality-provider-pk` The finality provider Schnorr BTC public key in hex format.
- `--staking-amount` The amount of satoshis to be locked.
- `--staking-time` The amount of BTC blocks to lock for.
- `--magic-bytes` Magic bytes in op_return output in hex.
- `--covenant-committee-pks` BTC public keys of the covenant committee. For each
covenant pub key specified, the flag needs to be used again.
- `--covenant-quorum` Required quorum of covenant members to unbond.
- `--network` Specifies the BTC network this transaction will be sent, any of
`[mainnet, testnet3, regtest, simnet, signet]`.

For example to generate one staking transaction that locks `0.1` BTC for one
year, use `--staking-amount=10000000` and `--staking-time=52560`.

```shell
stakercli transaction create-phase1-staking-transaction \
  --staker-pk <staker_pk> \
  --staking-amount 10000000 --staking-time 52560 \
  --magic-bytes <bbn_4byte_identifier> \
  --finality-provider-pk <fp_pk_chosen> \
  --covenant-quorum 1 \
  --covenant-committee-pks 50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0 \
  --network signet

{
  "staking_tx_hex": "020000000002404b4c00000000002251204a4b057a9fa0510ccdce480fdac5a3cd12329993bac2517afb784a64d11fc1b40000000000000000496a4762627434002dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd5000000000"
}
```

## Fund Raw Transaction

The generated raw transaction needs to be funded. To fund a transaction run
[`bitcoin-cli fundrawtransaction`](https://chainquery.com/bitcoin-cli/fundrawtransaction)
that adds inputs to a transaction until it has enough value to satisfy the transaction.

```shell
bitcoin-cli -signet \
  -rpcuser=<your_rpc_username> \
  -rpcpassword=<your_rpc_password> \
  -rpcport=38332 \
  -rpcwallet=btc-staker \
  fundrawtransaction 020000000002404b4c00000000002251204a4b057a9fa0510ccdce480fdac5a3cd12329993bac2517afb784a64d11fc1b40000000000000000496a4762627434002dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd5000000000

{
  "hex": "0200000001b8eba8646e5fdb240af853d52c37b6159984c34bebb55c6097c4f0d276e536c80000000000fdffffff0344770d000000000016001461e09f8a6e653c6bdec644874dc119be1b60f27a404b4c00000000002251204a4b057a9fa0510ccdce480fdac5a3cd12329993bac2517afb784a64d11fc1b40000000000000000496a4762627434002dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd5000000000",
  "fee": 0.00117500,
  "changepos": 0
}
```

> You might need to unlock the wallet with [`bitcoin-cli walletpassphrase`](https://chainquery.com/bitcoin-cli/walletpassphrase)

## Sign Transaction

For the transaction to be submitted to the BTC network it first needs to be signed.
You can sign the raw funded transaction and output the signed format as hex
using the
[`bitcoin-cli signrawtransactionwithwallet`](https://chainquery.com/bitcoin-cli/signrawtransactionwithwallet)
command.

> The transaction must be funded (`fundrawtransaction`) before is signed.

```shell
bitcoin-cli -signet \
  -rpcuser=<your_rpc_username> \
  -rpcpassword=<your_rpc_password> \
  -rpcport=38332 \
  -rpcwallet=btc-staker \
  signrawtransactionwithwallet 0200000001b8eba8646e5fdb240af853d52c37b6159984c34bebb55c6097c4f0d276e536c80000000000fdffffff0344770d000000000016001461e09f8a6e653c6bdec644874dc119be1b60f27a404b4c00000000002251204a4b057a9fa0510ccdce480fdac5a3cd12329993bac2517afb784a64d11fc1b40000000000000000496a4762627434002dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd5000000000

{
  "hex": "02000000000101b8eba8646e5fdb240af853d52c37b6159984c34bebb55c6097c4f0d276e536c80000000000fdffffff0344770d000000000016001461e09f8a6e653c6bdec644874dc119be1b60f27a404b4c00000000002251204a4b057a9fa0510ccdce480fdac5a3cd12329993bac2517afb784a64d11fc1b40000000000000000496a4762627434002dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd500247304402203bae17ac05c211e3c849595ef211f9a23ffc6d32d089e53cfaf81b94353f9e0c022063676b789a3fd85842552cd54408a8e92a1d37f51e0f4765ac29ef89ed707b750121032dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f355800000000",
  "complete": true
}
```

The output gives out the signed funded self-lock transaction in the `hex` property.

## Submit Transaction

The signed transaction can be submited onchain to BTC to be included in the blocks.
You can submit a transaction through the
[bitcoin-cli sendrawtransaction](https://chainquery.com/bitcoin-cli/sendrawtransaction)
that propagates the signed transaction to other nodes.

```shell
bitcoin-cli -signet \
  -rpcuser=<your_rpc_username> \
  -rpcpassword=<your_rpc_password> \
  -rpcport=38332 \
  sendrawtransaction 02000000000101ffa5874fdf64a535a4beae47ba0e66278b046baf7b3f3855dbf0413060aaeef90000000000fdffffff03404b4c00000000002251207c2649dc890238fada228d52a4c25fcef82e1cf3d7f53895ca0fcfb15dd142bb0000000000000000496a470102030400b91ea4619bc7b3f93e5015976f52f666ae4eb5c98018a6c8e41424905fa8591fa89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd50c876f7f70d0000001600141b9b57f4d4555e65ceb98c465c9580b0d6b0d0f60247304402200ae05daea3dc62ee7f2720c87705da28077ab19e420538eea5b92718271b4356022026c8367ac8bcd0b6d011842159cd525db672b234789a8d37725b247858c90a120121022dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f355800000000

e87cfd1bb8aaaa009acee0ed0c5a8bed4995c8d7bc34498031ae4dc2feb8ba41
```

It outputs the transaction hash. Wait a few minutes and make sure that
the transaction is included in the blockchain by using a Bitcoin explorer or
running the following command
[`bitcoin-cli gettransaction`](https://chainquery.com/bitcoin-cli/gettransaction).

```shell
bitcoin-cli -signet \
  -rpcuser=<your_rpc_username> \
  -rpcpassword=<your_rpc_password> \
  -rpcport=38332 \
  gettransaction e87cfd1bb8aaaa009acee0ed0c5a8bed4995c8d7bc34498031ae4dc2feb8ba41

{
  "amount": -0.05000000,
  "fee": -0.00117500,
  "confirmations": 2,
  "blockhash": "0000001779eb0be0537a3152ed8ced6dbf2e113617f0500c61c2db230df50f8b",
  "blockheight": 194352,
  "blockindex": 1,
  "blocktime": 1715001364,
  "txid": "e87cfd1bb8aaaa009acee0ed0c5a8bed4995c8d7bc34498031ae4dc2feb8ba41",
  "wtxid": "040de8ed63d6f7ab9d234bb203d2e26e5e46801c9a1fc5af62acbbd75c547602",
  "walletconflicts": [
  ],
  "time": 1715001117,
  "timereceived": 1715001117,
  "bip125-replaceable": "no",
  "details": [
    {
      "address": "tb1pff9s275l5pgsenwwfq8a43dre5fr9xvnhtp9z7hm0p9xf5glcx6q4ffjtg",
      "category": "send",
      "amount": -0.05000000,
      "vout": 1,
      "fee": -0.00117500,
      "abandoned": false
    },
    {
      "category": "send",
      "amount": 0.00000000,
      "vout": 2,
      "fee": -0.00117500,
      "abandoned": false
    }
  ],
  "hex": "02000000000101b8eba8646e5fdb240af853d52c37b6159984c34bebb55c6097c4f0d276e536c80000000000fdffffff0344770d000000000016001461e09f8a6e653c6bdec644874dc119be1b60f27a404b4c00000000002251204a4b057a9fa0510ccdce480fdac5a3cd12329993bac2517afb784a64d11fc1b40000000000000000496a4762627434002dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f3558a89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd500247304402203bae17ac05c211e3c849595ef211f9a23ffc6d32d089e53cfaf81b94353f9e0c022063676b789a3fd85842552cd54408a8e92a1d37f51e0f4765ac29ef89ed707b750121032dedbb66510d56b11f7a611e290f044e24dd48fd9c8a76d103ba05c8e95f355800000000",
  "lastprocessedblock": {
    "hash": "0000002afc7a3021b17967acf3d8a90af69023cc48383230dd29e782daf0ebdf",
    "height": 194353
  }
}
```
