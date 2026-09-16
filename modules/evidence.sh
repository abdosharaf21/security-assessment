#!/usr/bin/env bash
#
# Phase 6 - Evidence / Session Handling
#
# Usage:
#   ./modules/evidence.sh <target> [exploitation_dir]
#
# Turns the Phase 5 exploitation result into documented, lab-scoped
# evidence. Only data actually captured is written - nothing is invented.
#
# Handled states (honestly reported):
#   - exploitation not performed (no Phase 5 output / dependency missing)
#   - exploitation attempted but no session created
#   - session created (capable of collecting hostname/user/OS/network)
#
# Exit codes:
#   0  evidence gathered successfully (including a clear 'no session' record)
#   1  usage/technical error
#   2  no exploitation output to process (exploitation did not run)
#   3  required dependency missing where a live collection step is needed

set -uo pipefail

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=lib/common.sh
source "$COMMON_DIR/common.sh"

EXIT_OK=0
EXIT_ERROR=1
EXIT_NO_DATA=2
EXIT_DEPENDENCY=3

usage() {
    echo "Usage: $0 <target> [exploitation_dir]"
    echo "Example: $0 192.168.56.101"
    echo "         $0 192.168.56.101 output/exploitation/192.168.56.101_20260101_100000"
}

TARGET="${1:-}"
if [[ -z "$TARGET" ]] || ! sat_validate_target "$TARGET"; then
    usage
    exit "$EXIT_ERROR"
fi

sat_load_config || exit "$EXIT_ERROR"
sat_apply_defaults

SAFE_TARGET="$(sat_safe_name "$TARGET")"
EXPLOIT_DIR="${2:-}"
if [[ -z "$EXPLOIT_DIR" ]]; then
    EXPLOIT_DIR="$(sat_latest_dir_with "$OUTPUT_EXPLOIT" "$SAFE_TARGET" "result.txt")"
fi

if [[ -z "$EXPLOIT_DIR" || ! -d "$EXPLOIT_DIR" ]]; then
    echo "[-] No exploitation output found for target '$TARGET'." >&2
    echo "    Run Phase 5 first: ./modules/exploitation.sh $TARGET" >&2
    exit "$EXIT_NO_DATA"
fi

# Dependency-missing exploitation result -> honest evidence record
if [[ -f "$EXPLOIT_DIR/status.txt" ]] && grep -q "status=dependency-missing" "$EXPLOIT_DIR/status.txt"; then
    echo "[-] Phase 5 did not run (dependency missing). No exploitation evidence." >&2
    exit "$EXIT_NO_DATA"
fi

RESULT_FILE="$EXPLOIT_DIR/result.txt"
if [[ ! -f "$RESULT_FILE" ]]; then
    echo "[-] No result.txt in $EXPLOIT_DIR (Phase 5 did not record a result)." >&2
    exit "$EXIT_NO_DATA"
fi

OUT_FILE="$EXPLOIT_DIR/exploit_output.txt"
SESSION_STATUS="$(grep -E '^session_status=' "$RESULT_FILE" | head -n1 | cut -d= -f2-)"
SESSION_ID="$(grep -E '^session_id=' "$RESULT_FILE" | head -n1 | cut -d= -f2-)"
SESSION_TYPE="$(grep -E '^session_type=' "$RESULT_FILE" | head -n1 | cut -d= -f2-)"
MODULE="$(grep -E '^selected_module=' "$RESULT_FILE" | head -n1 | cut -d= -f2-)"

TIMESTAMP="$(sat_timestamp)"
DIR="$OUTPUT_EVIDENCE/${SAFE_TARGET}_${TIMESTAMP}"
mkdir -p "$DIR"

echo "========================================"
echo "        EVIDENCE / SESSION"
echo "========================================"
echo
echo "[*] Target:             $TARGET"
echo "[*] Exploitation dir:   $EXPLOIT_DIR"
echo "[*] Evidence output:    $DIR"
echo "[*] Session status:     ${SESSION_STATUS:-unknown}"
echo

# Preserve raw Phase 5 artifacts
if [[ -f "$OUT_FILE" ]]; then
    cp "$OUT_FILE" "$DIR/exploit_output.txt"
fi
if [[ -f "$EXPLOIT_DIR/msf_resource.res" ]]; then
    cp "$EXPLOIT_DIR/msf_resource.res" "$DIR/msf_resource.res"
fi

case "$SESSION_STATUS" in
    session-created)
        echo "[+] Session was created (${SESSION_TYPE} session ${SESSION_ID:-?})."
        {
            echo "session_status=$SESSION_STATUS"
            echo "session_type=${SESSION_TYPE:-}"
            echo "session_id=${SESSION_ID:-none}"
        } > "$DIR/session.txt"

        # Extract system/network evidence captured by sessions -C, if any.
        SYSTEM_NOTE="not captured (sessions -C output not found or unsupported)"
        if [[ -f "$OUT_FILE" ]] && grep -q "SAT_EVIDENCE_END" "$OUT_FILE"; then
            awk '/SAT_HOSTNAME_START/{f=1;next}/SAT_EVIDENCE_END/{f=0} f' "$OUT_FILE" > "$DIR/system_info.raw.txt"
            grep -vE '^(ip|br-|docker|veth|lo:|virbr)' "$DIR/system_info.raw.txt" | grep -E 'hostname|whoami|uid=|Linux|^[a-zA-Z0-9_.-]+$' > "$DIR/system_info.txt" 2>/dev/null || true
            grep -A100 "SAT_NET_START" "$OUT_FILE" | sed 's/^/    /' | grep -vE '^\s*SAT_' > "$DIR/network_info.raw.txt" || true
            SYSTEM_NOTE="captured (see exploit_output.txt)"
        fi

        {
            echo "Metadata for evidence collection (lab only)"
            echo "-------------------------------------------"
            echo "target=$TARGET"
            echo "timestamp=$TIMESTAMP"
            echo "exploit_dir=$EXPLOIT_DIR"
            echo "selected_module=${MODULE:-}"
            echo "session_type=${SESSION_TYPE:-}"
            echo "session_id=${SESSION_ID:-none}"
            echo "system_info=${SYSTEM_NOTE}"
        } > "$DIR/metadata.txt"
        ;;

    no-session)
        echo "[!] Exploitation attempted but no session was created."
        {
            echo "session_status=no-session"
            echo "session_id=none"
        } > "$DIR/session.txt"
        {
            echo "Metadata for evidence collection (lab only)"
            echo "-------------------------------------------"
            echo "target=$TARGET"
            echo "timestamp=$TIMESTAMP"
            echo "exploit_dir=$EXPLOIT_DIR"
            echo "selected_module=${MODULE:-}"
            echo "session_type=none"
            echo "session_id=none"
            echo "note=exploitation did not produce a session - no system evidence collected"
        } > "$DIR/metadata.txt"
        ;;

    *)
        echo "[!] Unknown/unhandled exploitation status: '${SESSION_STATUS}'"
        {
            echo "session_status=${SESSION_STATUS}"
            echo "session_id=none"
        } > "$DIR/session.txt"
        {
            echo "target=$TARGET"
            echo "timestamp=$TIMESTAMP"
            echo "exploit_dir=$EXPLOIT_DIR"
            echo "note=unhandled exploitation status - no system evidence collected"
        } > "$DIR/metadata.txt"
        ;;
esac

{
    echo "status=$SESSION_STATUS"
    echo "timestamp=$TIMESTAMP"
    echo "target=$TARGET"
} > "$DIR/status.txt"

python3 - "$DIR" "$TARGET" "$TIMESTAMP" "$SESSION_STATUS" "$SESSION_ID" "$SESSION_TYPE" "$MODULE" <<'PY'
import json
import os
import sys

ev_dir, target, ts, status, sid, stype, module = sys.argv[1:8]

def read(path):
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            return fh.read()
    return ''

payload = {
    'tool': 'security-assessment',
    'phase': 6,
    'phase_label': 'evidence-session-handling',
    'target': target,
    'timestamp': ts,
    'session_status': status,
    'session_id': sid if sid and sid != 'none' else '',
    'session_type': stype,
    'selected_module': module,
    'system_info': read(os.path.join(ev_dir, 'system_info.raw.txt')),
    'network_info': read(os.path.join(ev_dir, 'network_info.raw.txt')),
    'exploit_output': read(os.path.join(ev_dir, 'exploit_output.txt')),
}
with open(os.path.join(ev_dir, 'metadata.json'), 'w', encoding='utf-8') as fh:
    json.dump(payload, fh, indent=2)
PY

{
    echo "Phase 6 - Evidence / Session Handling"
    echo "Target: $TARGET"
    echo "Timestamp: $TIMESTAMP"
    echo
    echo "Session status detected: ${SESSION_STATUS:-unknown}"
    echo "Session id: ${SESSION_ID:-none}"
    echo
    echo "Files:"
    echo "  metadata.txt          - evidence metadata"
    echo "  metadata.json         - machine readable evidence"
    echo "  session.txt           - session record"
    echo "  exploit_output.txt    - preserved raw Metasploit output"
    echo "  msf_resource.res      - preserved resource script"
} > "$DIR/summary.txt"

echo
echo "------------------------------------------------------------"
cat "$DIR/summary.txt"
echo "------------------------------------------------------------"
echo
echo "[+] Phase 6 completed (honest record for state '$SESSION_STATUS')."
echo "[-] Output directory: $DIR"

case "$SESSION_STATUS" in
    session-created)
        exit "$EXIT_OK"
        ;;
    dependency-missing)
        exit "$EXIT_DEPENDENCY"
        ;;
    *)
        exit "$EXIT_NO_DATA"
        ;;
esac