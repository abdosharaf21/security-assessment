#!/usr/bin/env bash
#
# Phase 2 - Service Enumeration
#
# Usage:
#   ./modules/enumeration.sh <target>          # unprivileged run
#   sudo ./modules/enumeration.sh <target>     # enables OS detection (-O)
#
# Nmap settings are read from config/config.conf.
# The same variables may be overridden via the environment for testing.
#
# Exit codes:
#   0  open services discovered
#   1  usage/configuration/scan error
#   2  host unreachable
#   3  host reachable but no open TCP services found

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$PROJECT_ROOT/config/config.conf}"
OUTPUT_DIR="${OUTPUT_ENUM:-$PROJECT_ROOT/output/enumeration}"

EXIT_OK=0
EXIT_ERROR=1
EXIT_UNREACHABLE=2
EXIT_NO_OPEN=3

usage() {
    echo "Usage: $0 <target>"
    echo "Example: $0 10.0.2.15"
    echo "Root is recommended for OS detection: sudo $0 10.0.2.15"
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

apply_defaults() {
    NMAP_TIMING="${NMAP_TIMING:--T4}"
    NMAP_PORTS="${NMAP_PORTS:--p-}"
    NMAP_SERVICE_DETECTION="${NMAP_SERVICE_DETECTION:--sV}"
    NMAP_SCRIPTS="${NMAP_SCRIPTS:-default,vuln}"
    NMAP_OUTPUT_FORMAT="${NMAP_OUTPUT_FORMAT:-xml}"
}

# Cheap reachability probe before the expensive full scan.
# Sets REACHABLE=1 when the host answers ICMP or any TCP probe.
preflight() {
    local ping_ok=0 tcp_ok=0

    if ping -c1 -W2 "$TARGET" >/dev/null 2>&1; then
        ping_ok=1
    fi

    nmap \
        -Pn -n -sT -T4 --max-retries 1 --host-timeout 20s \
        --top-ports 100 "$TARGET" \
        -oN "$PREFLIGHT_OUT" >/dev/null 2>&1 || true

    if [[ -f "$PREFLIGHT_OUT" ]] && \
       grep -qE '[0-9]+/tcp[[:space:]]+(open|closed)' "$PREFLIGHT_OUT"; then
        tcp_ok=1
    fi

    echo "[*] Preflight reachability: ICMP=$([ "$ping_ok" -eq 1 ] && echo responding || echo no-response) TCP=$([ "$tcp_ok" -eq 1 ] && echo replying || echo no-response)"

    if (( ping_ok == 1 || tcp_ok == 1 )); then
        REACHABLE=1
    else
        REACHABLE=0
    fi
}

classify_result() {
    local txt="$1"
    local open_count closed_count no_response

    open_count=$(grep -cE '^[0-9]+/[0-9a-z]+[[:space:]]+open([[:space:]]|\|)' "$txt" || true)
    closed_count=$(grep -cE '^[0-9]+/[0-9a-z]+[[:space:]]+closed([[:space:]]|$)' "$txt" || true)
    no_response=$(grep -cE 'filtered tcp ports \(no-response\)' "$txt" || true)

    if (( open_count > 0 )); then
        echo
        echo "[+] OPEN SERVICES DISCOVERED ($open_count)"
        grep -E '^[0-9]+/[0-9a-z]+[[:space:]]+open([[:space:]]|\|)' "$txt" | while read -r line; do
            echo "    $line"
        done
        return "$EXIT_OK"
    fi

    if (( closed_count > 0 )); then
        echo
        echo "[!] Host reachable but no open TCP services were found."
        return "$EXIT_NO_OPEN"
    fi

    if (( no_response > 0 )); then
        if (( REACHABLE == 1 )); then
            echo
            echo "[!] Host reachable but all scanned TCP ports are filtered."
            return "$EXIT_NO_OPEN"
        fi
        echo
        echo "[-] HOST UNREACHABLE - no TCP responses were received."
        return "$EXIT_UNREACHABLE"
    fi

    echo
    echo "[-] Unable to classify the Nmap result."
    return "$EXIT_ERROR"
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
apply_defaults

SAFE_TARGET="${TARGET//[^a-zA-Z0-9_.-]/_}"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
OUTPUT_BASE="$OUTPUT_DIR/${SAFE_TARGET}_${TIMESTAMP}"
PREFLIGHT_OUT="$OUTPUT_BASE.preflight.txt"

echo "========================================"
echo "       SERVICE ENUMERATION"
echo "========================================"
echo
echo "[*] Target: $TARGET"
echo "[*] Scanning configuration:"
echo "    Timing:           $NMAP_TIMING"
echo "    Ports:            $NMAP_PORTS"
echo "    Detection:        $NMAP_SERVICE_DETECTION"
echo "    NSE scripts:      $NMAP_SCRIPTS"
echo

echo "[*] Running preflight reachability check..."
preflight

if (( REACHABLE != 1 )); then
    echo
    echo "[-] TARGET UNREACHABLE: $TARGET"
    echo "    No ICMP replies and no TCP responses were received from this host."
    echo "    The expensive full scan was skipped."
    echo
    echo "    Nmap preflight output saved to:"
    echo "    $PREFLIGHT_OUT"
    if [[ -f "$PREFLIGHT_OUT" ]]; then
        echo
        echo "    ------------------- nmap preflight output -------------------"
        sed -n '/scan report/,$p' "$PREFLIGHT_OUT" | sed -n '1,15p' | sed 's/^/    /'
        echo "    ------------------------------------------------------------"
    fi
    echo
    echo "    Possible causes: wrong target IP, wrong network adapter,"
    echo "    or no route from this host to the target subnet."
    exit "$EXIT_UNREACHABLE"
fi

echo "[+] Target appears reachable. Starting full service enumeration."
echo

OS_DETECTION=0
SCAN_TYPE="-sT"
if [[ $EUID -eq 0 ]]; then
    OS_DETECTION=1
    SCAN_TYPE="-sS"
    echo "[+] Running as root."
    echo "[+] OS detection (-O) ENABLED."
else
    echo "[!] Not running as root."
    echo "[!] OS detection (-O) SKIPPED - requires root privileges."
    echo "    Re-run as: sudo $0 $TARGET"
fi
echo

NMAP_ARGS=(
    "$NMAP_TIMING"
    "$NMAP_PORTS"
    "$NMAP_SERVICE_DETECTION"
    "$SCAN_TYPE"
    "-Pn"
    "-n"
    "--script=$NMAP_SCRIPTS"
)

if (( OS_DETECTION == 1 )); then
    NMAP_ARGS+=("-O")
fi

NMAP_CMD=( nmap "${NMAP_ARGS[@]}" "$TARGET" -oN "${OUTPUT_BASE}.txt" )
if [[ "$NMAP_OUTPUT_FORMAT" == *xml* ]]; then
    NMAP_CMD+=( -oX "${OUTPUT_BASE}.xml" )
fi

echo "[*] Running Nmap service enumeration:"
echo "    ${NMAP_CMD[*]}"
echo

"${NMAP_CMD[@]}"
NMAP_RC=$?

echo
if (( NMAP_RC == 2 )); then
    echo "[-] Nmap failed (exit code $NMAP_RC). See Nmap output above." >&2
    exit "$EXIT_ERROR"
fi

if (( NMAP_RC > 2 )); then
    echo "[!] Nmap finished with non-fatal exit code $NMAP_RC."
fi

echo "[*] Classification of results..."
classify_result "${OUTPUT_BASE}.txt"
RESULT=$?

echo
if [[ -f "${OUTPUT_BASE}.xml" ]]; then
    echo "[+] Text output:"
    echo "    ${OUTPUT_BASE}.txt"
    echo "[+] XML output:"
    echo "    ${OUTPUT_BASE}.xml"
else
    echo "[+] Text output:"
    echo "    ${OUTPUT_BASE}.txt"
fi
echo
echo "[-] Output directory: $OUTPUT_DIR"

exit "$RESULT"