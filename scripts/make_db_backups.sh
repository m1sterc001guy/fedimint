#!/usr/bin/env bash
# Runs the integration tests with the FM_TEST_DB_BACKUP_DIR environment variable configured.
# This script will run all of the integration tests and copy the databases for the federation
# members to `FM_TEST_DB_BACKUP_DIR`. These backed up databases can then be used to run 
# database migration tests with newer version of the fedimint and module code.

if [ -z "$1" ]
then
  FM_TEST_DB_BACKUP_DIR=$(realpath ./databases)
else
  FM_TEST_DB_BACKUP_DIR="$1"
fi

export FM_TEST_USE_REAL_DAEMONS=1
export FM_TEST_DB_BACKUP_DIR
source ./scripts/setup-tests.sh

echo "Executing integration tests and creating database backups at $FM_TEST_DB_BACKUP_DIR"
cargo test -p fedimint-tests -- --test-threads=1
