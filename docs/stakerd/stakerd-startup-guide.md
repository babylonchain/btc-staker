## Prerequisites

1. **Install Binaries:**
   Follow the instructions in
   the [installation section](../../README.md#2-installation) to install the required
   binaries.

2. **Staker Daemon Configuration:**
   Follow the instructions in the [Staker Daemon Configuration](stakerd-config.md)
   guide to configure the staker daemon.

## Starting the Staker Daemon

You can start the staker daemon using the following command:

```bash
$ stakerd
```

This will start the RPC server at the address specified in the configuration under
the `RawRPCListeners` field. A custom address can also be specified using
the `--rpclisten` flag.

```bash
$ stakerd --rpclisten 'localhost:8082'

time="2023-12-08T11:48:04+05:30" level=info msg="Starting StakerApp"
time="2023-12-08T11:48:04+05:30" level=info msg="Connecting to node backend: btcd"
```

All the available cli options can be viewed using the `--help` flag. These options
can also be set in the configuration file.
