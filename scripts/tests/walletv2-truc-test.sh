#!/usr/bin/env bash
# Runs the walletv2 TRUC batch test against a real bitcoind.
#
# The test asserts that a batch is broadcast as a zero-fee TRUC parent plus a
# fee-paying child, and that a peg-out recipient cannot attach any child to the
# parent — which is what kills both the oversized-child pin and cluster
# exhaustion (see PINNING.md). The mock bitcoin backend has no TRUC, no
# ephemeral dust and no package relay, so this only works against a real node.
#
# Any extra arguments are forwarded to `cargo nextest run`.

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
ensure_in_dev_shell
build_workspace
add_target_dir_to_path
make_fm_test_marker

EXTRA_ARGS=("$@")
export EXTRA_ARGS_STR="${EXTRA_ARGS[*]:-}"

function run_test() {
  set -euo pipefail

  export FM_TEST_USE_REAL_DAEMONS=1
  export RUST_BACKTRACE=1
  export RUST_LIB_BACKTRACE=0

  >&2 echo "### Running walletv2 TRUC batch test"

  # shellcheck disable=SC2086
  cargo nextest run --locked --workspace --all-targets \
    ${CARGO_PROFILE:+--cargo-profile ${CARGO_PROFILE}} ${CARGO_PROFILE:+--profile ${CARGO_PROFILE}} \
    --test-threads=1 ${EXTRA_ARGS_STR} \
    -E 'package(fedimint-walletv2-tests) & (test(truc_batch_is_packaged_and_cannot_be_pinned) + test(third_party_anchor_spend_settles_the_batch_on_the_parent))'
}
export -f run_test

devimint external-daemons --exec bash -c 'run_test'

echo "fm success: walletv2-truc-test"
