#!/usr/bin/env bash
set -Eeuo pipefail

IMAGE_ID="${1:-}"
RUNS="${2:-5}"
REPORT="${3:-/tmp/firmlab-full-system-reliability.json}"
API_BASE="${FIRMLAB_API_BASE:-http://127.0.0.1:8899/api}"
POLL_SECONDS="${FIRMLAB_RELIABILITY_POLL_SECONDS:-5}"
JOB_TIMEOUT_SECONDS="${FIRMLAB_RELIABILITY_JOB_TIMEOUT_SECONDS:-900}"

if [ -z "$IMAGE_ID" ]; then
  printf 'uso: scripts/verify-full-system-reliability.sh IMAGE_ID [runs=5] [report.json]\n' >&2
  exit 2
fi
case "$RUNS" in
  ''|*[!0-9]*) printf 'runs debe ser un entero positivo\n' >&2; exit 2 ;;
esac
if [ "$RUNS" -lt 1 ]; then printf 'runs debe ser un entero positivo\n' >&2; exit 2; fi
for tool in curl jq; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'falta la dependencia: %s\n' "$tool" >&2; exit 127; }
done

tmp="$(mktemp -d /tmp/firmlab-full-system-reliability.XXXXXX)"
cleanup() {
  find "$tmp" -type f -delete 2>/dev/null || true
  rmdir "$tmp" 2>/dev/null || true
}
trap cleanup EXIT

for ((run = 1; run <= RUNS; run++)); do
  job_id="$(curl --fail --silent --show-error \
    -H 'content-type: application/json' \
    -d '{"rung":"full-system"}' \
    "$API_BASE/images/$IMAGE_ID/emulate-system" | jq -er '.jobId')"
  printf '[%s/%s] job %s iniciado\n' "$run" "$RUNS" "$job_id" >&2
  started="$(date +%s)"
  while :; do
    envelope="$(curl --fail --silent --show-error "$API_BASE/jobs/$job_id")"
    status="$(printf '%s' "$envelope" | jq -er '.job.status')"
    if [ "$status" = done ] || [ "$status" = error ]; then break; fi
    now="$(date +%s)"
    if [ $((now - started)) -ge "$JOB_TIMEOUT_SECONDS" ]; then
      printf '[%s/%s] job %s excedió %ss (estado %s)\n' "$run" "$RUNS" "$job_id" "$JOB_TIMEOUT_SECONDS" "$status" >&2
      exit 1
    fi
    sleep "$POLL_SECONDS"
  done
  printf '%s\n' "$envelope" > "$tmp/job-$run.json"
  printf '[%s/%s] job %s terminó: %s\n' "$run" "$RUNS" "$job_id" "$status" >&2
  if [ "$status" != done ]; then
    printf '%s\n' "$envelope" | jq -r '.job.error, .job.log' >&2
    exit 1
  fi
done

jq -s '
  {
    schemaVersion: 1,
    imageId: $imageId,
    requestedRuns: $requestedRuns,
    measuredAt: (now | todateiso8601),
    runs: map(.job | {
      jobId: .id,
      status,
      proofState: .result.proofState,
      buildRev: .result.buildRev,
      unmodifiedOpenGuestPorts: [.result.open[]?.guest],
      passes: [.result.passes[]? | {pass, label, booted, panicked, timedOut, openGuestPorts: [.open[]?.guest]}],
      reproducibility: .result.reproducibility,
      console: {
        attempted: (.result.console.attempted // false),
        shellAnswered: (.result.console.outcome.shellAnswered // false),
        policyBefore: (.result.console.outcome.policyBefore // null),
        policyAfter: (.result.console.outcome.policyAfter // null),
        teardownRan: (.result.console.outcome.teardownRan // false),
        openGuestPorts: [.result.console.open[]?.guest],
        interventions: (.result.console.interventions // [])
      },
      liveWebProbes: [.result.webProbes[]? | {
        pass,
        guest,
        available: .result.available,
        requests: .result.requests,
        points: .result.points,
        findings: (.result.findings | length),
        interventions: (.interventions // [])
      }]
    })
  }
  | .checks = {
      allJobsDone: ([.runs[].status == "done"] | all),
      oneBuild: (([.runs[].buildRev] | unique | length) == 1 and (.runs[0].buildRev != null)),
      stableHeadline: (([.runs[].proofState] | unique | length) == 1),
      noPanics: ([.runs[].passes[]?.panicked == false] | all),
      consoleRecoveredEveryRun: ([.runs[] | (.console.attempted and .console.shellAnswered and .console.teardownRan and .console.policyBefore == "DROP" and .console.policyAfter == "ACCEPT" and (.console.openGuestPorts | index(80) != null))] | all),
      liveHttpProbedEveryRun: ([.runs[] | any(.liveWebProbes[]?; .pass == 3 and .guest == 80 and .available and .requests > 0 and (.interventions | length) > 0)] | all),
      reproducibilityStableAtFive: ((.runs[-1].reproducibility.kind == "stable") and (.runs[-1].reproducibility.n >= 5))
    }
  | .success = ([.checks[]] | all)
' --arg imageId "$IMAGE_ID" --argjson requestedRuns "$RUNS" "$tmp"/job-*.json > "$REPORT"

jq . "$REPORT"
if [ "$(jq -r '.success' "$REPORT")" != true ]; then
  printf 'la campaña terminó, pero uno o más criterios de fiabilidad fallaron: %s\n' "$REPORT" >&2
  exit 1
fi
printf 'cinco arrancadas verificadas: %s\n' "$REPORT" >&2
