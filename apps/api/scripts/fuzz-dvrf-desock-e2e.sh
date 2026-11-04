#!/usr/bin/env bash
# Real-daemon smoke for the packaged MIPSel/uClibc desocket preload. Run only in a disposable --network none
# container with the local firmware data volume mounted read-only; it never writes to the rootfs or database.
# Keep the disposable container's /var/run writable because DVRF httpd creates an ephemeral PID file there.
set -euo pipefail
rootfs="${DVRF_ROOTFS:-/data/extract/2be9f9b8/_DVRF_v03.bin.extracted/squashfs-root}"
preload="${FIRMLAB_DESOCK:-/opt/desock/libaflppdesock-mipsel-uclibc.so}"
target="$rootfs/usr/sbin/httpd"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

test -x "$target"
test -f "$preload"
if [ ! -w /var/run ]; then
  echo 'FAIL /var/run is not writable; DVRF httpd needs an ephemeral PID file in the disposable container' >&2
  exit 1
fi
readelf -d "$preload" | grep -q 'Shared library: \[libdl.so.0\]'
if readelf -d "$preload" | grep -q 'libc.so.6'; then
  echo 'FAIL preload carries a glibc dependency' >&2
  exit 1
fi

set +e
printf 'GET / HTTP/1.0\r\nHost: firmlab\r\n\r\n' | timeout 12 \
  qemu-mipsel-static -L "$rootfs" \
  -E LD_PRELOAD="$preload" -E DESOCK_PORT=80 -E DESOCK_FORK=1 -E DESOCK_CLOSE_EXIT=1 -E DESOCK_DEBUG=1 \
  "$target" -p 80 >"$work/correct.out" 2>"$work/correct.err"
correct_port_exit=$?
set -e
if [ "$correct_port_exit" -ne 0 ]; then
  echo "FAIL correct-port control exited $correct_port_exit" >&2
  sed -n '1,120p' "$work/correct.err" >&2
  exit 1
fi
grep -q 'DESOCK: intercepted bind' "$work/correct.err"
grep -q 'DESOCK: intercepted listen' "$work/correct.err"
grep -q 'DESOCK: intercepted accept' "$work/correct.err"
grep -q 'DESOCK: intercepted fdopen(r+) for 0' "$work/correct.err"
grep -q 'DESOCK: exiting' "$work/correct.err"

set +e
printf 'GET / HTTP/1.0\r\nHost: firmlab\r\n\r\n' | timeout 5 \
  qemu-mipsel-static -L "$rootfs" \
  -E LD_PRELOAD="$preload" -E DESOCK_PORT=81 -E DESOCK_FORK=1 -E DESOCK_CLOSE_EXIT=1 -E DESOCK_DEBUG=1 \
  "$target" -p 80 >"$work/wrong.out" 2>"$work/wrong.err"
wrong_port_exit=$?
set -e
if [ "$wrong_port_exit" -ne 124 ]; then
  echo "FAIL wrong-port control exited $wrong_port_exit instead of timing out" >&2
  exit 1
fi
if grep -q 'DESOCK: intercepted accept' "$work/wrong.err"; then
  echo 'FAIL wrong-port control intercepted accept' >&2
  exit 1
fi

echo 'RESULT: PASS — DVRF httpd port 80 consumed stdin through the MIPSel/uClibc desocket channel; port 81 did not.'
