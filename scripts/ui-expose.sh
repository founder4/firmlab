#!/usr/bin/env bash
#
# Reach the DEPLOYED workbench from a browser on this host, without copying its data or starting a second writer.
#
# The container publishes no host port by design (the homelab compose fronts it with Traefik), which is right for
# exposure and leaves the UI unviewable from a local browser. Copying `/data` is 2 GB, and a second container on the
# same volume is two writers on one SQLite file — the lock conflict `mcp/server.ts` was deliberately designed around.
# A socat sidecar on the same docker network is neither: one process, read-only with respect to state, torn down in
# one command. The published port is LOOPBACK-ONLY, and deliberately not 8799 — that is the port `deploy.sh`'s
# anti-squatter check watches, and a listener there is exactly the ghost that already cost this project real
# debugging time.
#
#   scripts/ui-expose.sh up     → http://127.0.0.1:8899
#   scripts/ui-expose.sh down
set -Eeuo pipefail

PORT="${FIRMLAB_UI_PORT:-8899}"
NAME=firmlab-view
TARGET="${FIRMLAB_CONTAINER:-firmlab}"

case "${1:-up}" in
  up)
    net="$(docker inspect "$TARGET" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')"
    [ -n "$net" ] || { echo "no se encontró la red de $TARGET" >&2; exit 1; }
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --rm --name "$NAME" --network "$net" -p "127.0.0.1:$PORT:8799" \
      alpine/socat "TCP-LISTEN:8799,fork,reuseaddr" "TCP:$TARGET:8799" >/dev/null
    sleep 2
    curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null && echo "==> http://127.0.0.1:$PORT (contenedor $TARGET)"
    ;;
  down)
    docker rm -f "$NAME" >/dev/null 2>&1 && echo "==> $NAME retirado" || echo "==> $NAME no estaba levantado"
    ;;
  *) echo "uso: $0 [up|down]" >&2; exit 2 ;;
esac
