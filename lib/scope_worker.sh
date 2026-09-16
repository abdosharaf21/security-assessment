#!/usr/bin/env bash
#
# Scope target worker (Phase 11/13) - runs the non-exploit phase pipeline
# for ONE target inside a bounded worker pool. Each worker has its own
# isolated output dirs; a failure or timeout in one worker never corrupts
# another target's artifacts.
#
# Usage: scope_worker.sh <assessment_id> <scope_id> <target>
#
# Pipeline: discovery -> enumeration -> vulnerabilities -> correlation.
# Exploitation is NEVER part of this worker (it is approval-gated and
# explicit only). Per-target state is written atomically per worker.
#
# Exit codes: 0 completed; non-zero records a failed phase. 124 (via the
# outer `timeout`) records a bounded-run timeout - never success.

set -uo pipefail

WORKER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$WORKER_ROOT/config/config.conf}"

source "$WORKER_ROOT/lib/common.sh"
source "$WORKER_ROOT/lib/assessment.sh"
source "$WORKER_ROOT/lib/scope.sh"

AID="${1:-}"
SID="${2:-}"
TARGET="${3:-}"
if [[ -z "$AID" || -z "$SID" || -z "$TARGET" ]]; then
    echo "[-] scope_worker: missing arguments" >&2
    exit 1
fi

KEY="$(sat_safe_name "$TARGET")"
TARGET_BASE="$ASSESSMENTS_ROOT/$AID/scopes/$SID/targets/$KEY"
mkdir -p "$TARGET_BASE"

# Outputs stay inside this worker's own directory: no shared files.
export OUTPUT_NMAP="$TARGET_BASE/discovery"
export OUTPUT_ENUM="$TARGET_BASE/enumeration"
export OUTPUT_VULN="$TARGET_BASE/vulnerabilities"
export OUTPUT_EXPLOIT="$TARGET_BASE/exploitation"
export OUTPUT_EVIDENCE="$TARGET_BASE/evidence"
export OUTPUT_REPORTS="$TARGET_BASE/report"

# A bounded run that was killed (outer `timeout`) must record a timeout,
# never a silent success. Running phases in the background means bash's
# `wait` is interruptible: TERM runs this trap immediately instead of
# waiting for the long-running phase child to finish on its own.
scope_worker_term() {
    local wpid="${WPID:-}"
    if [[ -n "$wpid" ]]; then
        kill "$wpid" 2>/dev/null || true
    fi
    sat_scope_target_abort "$SID" "$TARGET" "bounded-run timeout exceeded" 124 || true
    exit 124
}
trap scope_worker_term TERM INT

sat_scope_target_begin "$SID" "$TARGET" || exit 1

# A non-zero phase rc is "tolerable" (= valid no-data outcome) only for
# known empty-result cases. Anything else is a real failure.
ENUM_RC=0
PIPELINE="discovery enumeration vulnerabilities correlation"
for phase in $PIPELINE; do
    sat_scope_target_phase "$SID" "$TARGET" "$phase" running 0
    "$WORKER_ROOT/modules/$(sat_assessment_module_name "$phase")" "$TARGET" >/dev/null 2>&1 &
    WPID=$!
    wait "$WPID"
    PHASE_RC=$?
    if [[ "$phase" == "enumeration" ]]; then
        ENUM_RC="$PHASE_RC"
    fi
    if (( PHASE_RC != 0 )); then
        tolerable=0
        case "$phase:$PHASE_RC" in
            enumeration:3) tolerable=1 ;;                       # reachable, no open ports
            vulnerabilities:2) [[ "$ENUM_RC" == "3" ]] && tolerable=1 ;;  # no ports -> no XML
        esac
        if (( tolerable == 1 )); then
            sat_scope_target_phase "$SID" "$TARGET" "$phase" completed "$PHASE_RC"
            echo "[*] $TARGET: phase '$phase' completed with no-data (rc=$PHASE_RC)"
            continue
        fi
        local_reason="phase ${phase} failed (rc=$PHASE_RC)"
        if [[ "$phase" == "discovery" && "$PHASE_RC" == 2 ]]; then
            local_reason="host unreachable"
        fi
        sat_scope_target_phase "$SID" "$TARGET" "$phase" failed "$PHASE_RC"
        sat_scope_target_fail "$SID" "$TARGET" "$local_reason" "$PHASE_RC"
        echo "[!] $TARGET: $local_reason"
        exit "$PHASE_RC"
    fi
    sat_scope_target_phase "$SID" "$TARGET" "$phase" completed 0
    echo "[+] $TARGET: phase '$phase' completed"
done

sat_scope_target_complete "$SID" "$TARGET"
echo "[+] $TARGET: target completed"
exit 0