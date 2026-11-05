#!/usr/bin/env bash
#
# Starts a mempool.space explorer at http://localhost:8080 for the running
# devimint federation's regtest chain, with an empty database every time.
# The containers keep running in the background until stopped.
#
# Usage: ./run-mempool.sh        start, replacing any running explorer
#        ./run-mempool.sh stop   stop it

set -euo pipefail

BACKEND_IMAGE=mempool/backend:v3.3.2
FRONTEND_IMAGE=mempool/frontend:v3.3.2
DATABASE_IMAGE=mariadb:10.5.21

# The containers use the host's network to reach devimint's ports on
# 127.0.0.1, so their own ports are taken on the host too.
FRONTEND_PORT=8080
BACKEND_PORT=8999
DATABASE_PORT=3307

DATABASE=devimint-mempool-db
BACKEND=devimint-mempool-backend
FRONTEND=devimint-mempool-frontend

# Removing the database container wipes the database: it lives in a tmpfs.
stop() {
  docker rm -f "$FRONTEND" "$BACKEND" "$DATABASE" >/dev/null 2>&1 || true
}

case "${1:-}" in
  "") ;;
  stop)
    stop
    echo "Stopped mempool" >&2
    exit 0
    ;;
  *)
    echo "Usage: $0 [stop]" >&2
    exit 1
    ;;
esac

DEVIMINT_ENV="${DEVIMINT_ENV:-$(dirname "${BASH_SOURCE[0]}")/target-nix/devimint/env}"

# Set inside the devimint shell; elsewhere, read from devimint's env file.
if [ -z "${FM_PORT_BTC_RPC:-}" ] || [ -z "${FM_PORT_ESPLORA:-}" ] ||
  [ -z "${FM_PORT_ESPLORA_ELECTRUM:-}" ]; then
  if [ ! -f "$DEVIMINT_ENV" ]; then
    echo "No devimint env at $DEVIMINT_ENV: run 'FM_ENABLE_MODULE_STATECHAIN=1 just devimint-env' first" >&2
    exit 1
  fi
  FM_PORT_BTC_RPC=$(sed -n 's/^export FM_PORT_BTC_RPC="\([0-9]*\)"$/\1/p' "$DEVIMINT_ENV")
  FM_PORT_ESPLORA=$(sed -n 's/^export FM_PORT_ESPLORA="\([0-9]*\)"$/\1/p' "$DEVIMINT_ENV")
  FM_PORT_ESPLORA_ELECTRUM=$(sed -n 's/^export FM_PORT_ESPLORA_ELECTRUM="\([0-9]*\)"$/\1/p' "$DEVIMINT_ENV")
fi

if ! curl -sf --max-time 5 "http://127.0.0.1:$FM_PORT_ESPLORA/blocks/tip/height" >/dev/null; then
  echo "Esplora is not answering at 127.0.0.1:$FM_PORT_ESPLORA: is devimint running?" >&2
  exit 1
fi

stop

docker run -d --name "$DATABASE" --network host --tmpfs /var/lib/mysql \
  -e MYSQL_DATABASE=mempool \
  -e MYSQL_USER=mempool \
  -e MYSQL_PASSWORD=mempool \
  -e MYSQL_ROOT_PASSWORD=mempool \
  "$DATABASE_IMAGE" --port="$DATABASE_PORT" --bind-address=127.0.0.1 >/dev/null

# The backend gives up if the database is not up when it starts.
for _ in $(seq 60); do
  if docker exec "$DATABASE" mysqladmin ping --host=127.0.0.1 --port="$DATABASE_PORT" \
    --user=mempool --password=mempool --silent >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# Reads devimint's electrs through its Electrum port: mempool's esplora
# backend needs endpoints only mempool's own electrs fork serves.
docker run -d --name "$BACKEND" --network host \
  -e MEMPOOL_NETWORK=regtest \
  -e MEMPOOL_BACKEND=electrum \
  -e ELECTRUM_HOST=127.0.0.1 \
  -e ELECTRUM_PORT="$FM_PORT_ESPLORA_ELECTRUM" \
  -e ELECTRUM_TLS_ENABLED=false \
  -e CORE_RPC_HOST=127.0.0.1 \
  -e CORE_RPC_PORT="$FM_PORT_BTC_RPC" \
  -e CORE_RPC_USERNAME=bitcoin \
  -e CORE_RPC_PASSWORD=bitcoin \
  -e DATABASE_HOST=127.0.0.1 \
  -e DATABASE_PORT="$DATABASE_PORT" \
  -e BACKEND_HTTP_PORT="$BACKEND_PORT" \
  "$BACKEND_IMAGE" >/dev/null

# Serves regtest at the root, where the frontend's API routes point.
docker run -d --name "$FRONTEND" --network host \
  -e FRONTEND_HTTP_PORT="$FRONTEND_PORT" \
  -e BACKEND_MAINNET_HTTP_HOST=127.0.0.1 \
  -e BACKEND_MAINNET_HTTP_PORT="$BACKEND_PORT" \
  -e MAINNET_ENABLED=false \
  -e REGTEST_ENABLED=true \
  -e ROOT_NETWORK=regtest \
  "$FRONTEND_IMAGE" >/dev/null

echo "mempool is starting at http://localhost:$FRONTEND_PORT (stop it with $0 stop)" >&2
