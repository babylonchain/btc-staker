## 1. Overview

BTC-Staker program offers a comprehensive toolset to manage your Bitcoin staking
experience. It consists of two components:

- **stakerd:**  A daemon handling connections to the Babylon node and Bitcoin node,
  managing all aspects of staking in the background.
- **stakercli:**  A command-line interface (CLI) for interacting with stakerd,
  allowing you to:
    - **Stake:**  Submit requests, specifying amount, validator, and duration.
    - **Unstake:**  Initiate the process to gradually retrieve your staked funds.
    - **Unbond:**  Manage and monitor unstaked funds and their release timeline.
    - **View details:**  Access information about your staking history, individual
      transactions, and earned rewards.
    - **List transactions:**  Get a chronological list of all staking-related
      transactions.
    - **Manage outputs:**  View and control your Bitcoin outputs associated with
      staking.
    - **Access Babylon:**  Explore and interact with available Babylon validators.

## 2. Installation

#### Prerequisites

This project requires Go version 1.21 or later.

Install Go by following the instructions on
the [official Go installation guide](https://golang.org/doc/install).

#### Downloading the code

To get started, clone the repository to your local machine from Github:

```bash  
$ git clone git@github.com:babylonchain/btc-staker.git
```  

You can choose a specific version from
the [official releases page](https://github.com/babylonchain/btcstaker/releases)

```bash  
$ cd btc-staker # cd into the project directory$ git checkout <release-tag>```  
  
#### Building and installing the binary  
  
```bash  
# cd into the project directory  
$ cd btc-staker   
# installs the compiled binaries to your  
# $GOPATH/bin directory allowing access  
# from anywhere on your system  
$ make install   
```  

The above will produce the following binaries:

- `stakerd`: The daemon program for the btc-staker
- `stakercli`: The CLI tool for interacting with the stakerd.

To build locally,

```bash
$ cd btc-staker # cd into the project directory
$ make build
```

The above will lead to a build directory having the following structure:

```bash
$ ls build
    ├── stakerd
    └── stakercli
```
