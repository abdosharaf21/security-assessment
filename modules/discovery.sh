#!/usr/bin/env bash
#
# Phase 1 - Host Discovery
#
# Usage: ./modules/discovery.sh <target>
#
# Performs a lightweight host discovery (ICMP + ARP via Nmap ping scan)
# and classifies the target as up or down.
#
# Exit codes:
#   0  host is up
#   1  usage/configuration error
#   2  host is not responding to discovery probes

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$PROJECT_ROOT/config/config.conf}"
OUTPUT_DIR="${OUTPUT_NMAP:-$PROJECT_ROOT/output/nmap}"

EXIT_UP=0
EXIT_ERROR=1
EXIT_DOWN=2

usage() {
    echo "Usage: $0 <target>"
    echo "Example: $0 10.0.2.15"
}

# config.conf -> shell variables (environment variables win)
load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "[-] Configuration file not found: $CONFIG_FILE" >&2
        return 1
    fi

    local key value
    while IFS='=' read -r key value; do
        key="${key//[[:space:]]/}"
        [[ -z "$key" || "$key" == \#* ]] && continue
        [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
        if [[ -n "${!key:-}" ]]; then
            continue
        fi
        value="${value%\"}"
        value="${value#\"}"
        value="${value%\'}"
        value="${value#\'}"
        export "$key=$value"
    done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$CONFIG_FILE" || true)
}

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    usage
    exit "$EXIT_ERROR"
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "[-] nmap is not installed." >&2
    exit "$EXIT_ERROR"
fi

if ! mkdir -p "$OUTPUT_DIR"; then
    echo "[-] Could not create output directory: $OUTPUT_DIR" >&2
    exit "$EXIT_ERROR"
fi

load_config || exit "$EXIT_ERROR"

NMAP_TIMING="${NMAP_TIMING:--T4}"
NMAP_OUTPUT_FORMAT="${NMAP_OUTPUT_FORMAT:-xml}"

SAFE_TARGET="${TARGET//[^a-zA-Z0-9_.-]/_}"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
OUTPUT_BASE="$OUTPUT_DIR/${SAFE_TARGET}_${TIMESTAMP}"

echo "========================================"
echo "         HOST DISCOVERY"
echo "========================================"
echo
echo "[*] Target: $TARGET"
echo "[*] Running Nmap host discovery (ping scan)..."
echo

NMAP_CMD=( nmap -sn -n "$NMAP_TIMING" "$TARGET" -oN "${OUTPUT_BASE}.txt" )
if [[ "$NMAP_OUTPUT_FORMAT" == *xml* ]]; then
    NMAP_CMD+=( -oX "${OUTPUT_BASE}.xml" )
fi

"${NMAP_CMD[@]}" || true

HOST_UP=0
if grep -qE 'Host is up' "${OUTPUT_BASE}.txt"; then
    HOST_UP=1
fi

echo
if (( HOST_UP == 1 )); then
    echo "[+] Target $TARGET is UP."
else
    echo "[-] Target $TARGET is DOWN (no response to discovery probes)."
fi
echo
echo "[+] Output:"
echo "    ${OUTPUT_BASE}.txt"
if [[ -f "${OUTPUT_BASE}.xml" ]]; then
    echo "    ${OUTPUT_BASE}.xml"
fi

if (( HOST_UP == 1 )); then
    exit "$EXIT_UP"
else
    exit "$EXIT_DOWN"
fi