#!/usr/bin/env bash

source ./scripts/lib.sh

# First wait 1s for the federation (started itself with a 1s delay after bitcoind)
sleep 2

POLL_INTERVAL=0.5
export POLL_INTERVAL

echo Setting up bitcoind ...
btc_client createwallet default | show_verbose_output
mine_blocks 101 | show_verbose_output

# Wait for the lightning clients to start (ln1 and ln2 are started with a 5s delay after bitcoind and deferation start)
# FIXME: After tackling https://github.com/fedimint/fedimint/issues/699, this can be removed
await_block_sync

echo Setting up lightning channel ...
open_channel | show_verbose_output

echo Funding user e-cash wallet ...
scripts/pegin.sh 10000.0 | show_verbose_output

echo Connecting federation to gateway
gw_connect_fed

echo Funding gateway e-cash wallet ...
scripts/pegin.sh 20000.0 1 | show_verbose_output

echo Done!
echo
echo "This shell provides the following commands:"
echo "  fedimint-cli:  cli client to interact with the federation"
echo "  ln1, ln2:     cli clients for the two lightning nodes (1 is gateway)"
echo "  btc_client:   cli client for bitcoind"
echo "  gateway-cli:  cli client for the gateway"
echo
echo Use fedimint-cli as follows:
fedimint-cli --help
