#!/usr/bin/env bash
#
# Reach the DEPLOYED workbench from a browser on this host, without copying its data or starting a second writer.
#
# The container publishes no host port by design (the homelab compose fronts it with Traefik), which is right for
# exposure and leaves the UI unviewable from a local browser. Copying `/data` is 2 GB, and a second container on the
# same volume is two writers on one SQLite file — the lock conflict `mcp/server.ts` was deliberately designed around.
# The homelab compose normally provides a permanent socat sidecar on this port. This script reuses that endpoint
# when it is healthy; otherwise it may create a separately named, explicitly labelled fallback. `down` only removes
# that fallback. The published port is LOOPBACK-ONLY, and deliberately not 8799 — that is the port `deploy.sh`'s
# anti-squatter check watches, and a listener there is exactly the ghost that already cost this project real
# debugging time.
#
#   scripts/ui-expose.sh up     → http://127.0.0.1:8899
#   scripts/ui-expose.sh down
set -Eeuo pipefail

PORT="${FIRMLAB_UI_PORT:-8899}"
NAME="${FIRMLAB_UI_CONTAINER:-firmlab-ui-expose}"
TARGET="${FIRMLAB_CONTAINER:-firmlab}"
OWNER_LABEL=io.firmlab.ui-expose

healthy_endpoint() {
  local response
  response="$(curl -fsS --max-time 3 "http://127.0.0.1:$PORT/health" 2>/dev/null)" || return 1
  grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"' <<<"$response"
}

container_label() {
  docker inspect "$NAME" --format "{{index .Config.Labels \"$1\"}}" 2>/dev/null || true
}

remove_owned_sidecar() {
  docker inspect "$NAME" >/dev/null 2>&1 || return 1

  local owner compose_project
  owner="$(container_label "$OWNER_LABEL")"
  compose_project="$(container_label com.docker.compose.project)"
  if [ "$owner" != 1 ] || [ -n "$compose_project" ]; then
    echo "se rechaza retirar $NAME: no es un sidecar creado por ui-expose" >&2
    return 2
  fi

  docker rm -f "$NAME" >/dev/null
}

case "${1:-up}" in
  up)
    if healthy_endpoint; then
      echo "==> http://127.0.0.1:$PORT ya está disponible; no se modifica ningún contenedor"
      exit 0
    fi

    net="$(docker inspect "$TARGET" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')"
    [ -n "$net" ] || { echo "no se encontró la red de $TARGET" >&2; exit 1; }
    if docker inspect "$NAME" >/dev/null 2>&1; then
      remove_owned_sidecar
    fi
    docker run -d --rm --name "$NAME" --label "$OWNER_LABEL=1" --network "$net" \
      -p "127.0.0.1:$PORT:8799" \
      alpine/socat "TCP-LISTEN:8799,fork,reuseaddr" "TCP:$TARGET:8799" >/dev/null
    sleep 2
    curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null && echo "==> http://127.0.0.1:$PORT (contenedor $TARGET)"
    ;;
  down)
    if remove_owned_sidecar; then
      echo "==> $NAME retirado"
    else
      status=$?
      if [ "$status" -eq 1 ]; then
        echo "==> $NAME no estaba levantado"
        exit 0
      fi
      exit "$status"
    fi
    ;;
  *) echo "uso: $0 [up|down]" >&2; exit 2 ;;
esac
