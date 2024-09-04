#!/usr/bin/env bash
# Runs a test to make sure gateways can reboot properly, with the expected state

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker


#devimint gateway-reboot-test
gateway-tests backup-restore-test
