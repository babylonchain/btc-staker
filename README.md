## 1. Overview

BTC-Staker is a powerful toolset designed for seamless Bitcoin staking, consisting of
the stakerd Daemon and the stakercli Command-Line Interface (CLI).

1. stakerd Daemon The stakerd Daemon manages connections to the Babylon and Bitcoin
   nodes, handling all aspects of staking in the background for a hassle-free
   experience.

2. stakercli Command-Line Interface (CLI)
   The stakercli CLI facilitates interaction with the stakerd Daemon, enabling users
   to stake funds, withdraw funds, unbond staked funds, retrieve the active validator
   set in Babylon, and more. It serves as an intuitive interface for effortless
   control and monitoring of your Bitcoin staking activities.

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
