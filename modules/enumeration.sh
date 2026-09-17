#!/usr/bin/env bash
#
# Phase 2 - Service Enumeration (V2, multi-stage)
#
# Usage:
#   ./modules/enumeration.sh <target>          # unprivileged run
#   sudo ./modules/enumeration.sh <target>     # enables OS detection (-O)
#
# Pipeline:
#   Stage 1 - Port discovery
#     Discovers open TCP ports through the existing target/scope validation
#     layer (sat_validate_target). Port selection is configurable:
#       ENUM_PORT_MODE=top    => top-N TCP ports (ENUM_TOP_PORTS, default 100)
#       ENUM_PORT_MODE=all    => all 65535 TCP ports (-p-)
#       ENUM_PORT_MODE=custom => NMAP_PORTS (-p <list/range>)
#     An explicitly exported NMAP_PORTS is always honored as 'custom'.
#
#   Stage 2 - Targeted service enumeration
#     Runs only against the discovered ports (never re-scans unrelated ports):
#       nmap -T4 -sV -sC -Pn -n -p <discovered_ports> TARGET
#     Nmap XML is parsed with the Python standard-library ElementTree API.
#     No external XML library is required. Malformed/truncated XML and
#     incomplete Nmap output fall back to the text artifact and are recorded
#     honestly (status=partial) - never silently discarded.
#
#   Stage 3 - Service-specific enumeration (modular, read-only)
#     Dispatches handler scripts from modules/service_handlers/ for each
#     discovered service. Handlers are safe/non-exploitative by design;
#     missing dependencies are recorded as skipped, never fatal. New handlers
#     can be added by dropping a "<name>_handler.sh" file (see handler header).
#
# Exit codes:
#   0  open services discovered (findings may be partial - see status file)
#   1  usage/configuration/technical error (nmap failure or timeout)
#   2  host unreachable
#   3  host reachable but no open TCP services found
#
# Artifacts (base = output/enumeration/<safe>_<timestamp>):
#   base.ports.txt / base.ports.tsv / base.ports.xml  - Stage 1
#   base.txt / base.xml                               - Stage 2 (targeted)
#   base.services.tsv / base.services.txt             - parsed Stage 2
#   base.status.txt                                   - pipeline status
#   base.diagnostics.log                              - warnings (never silent)
#   base.stage3/                                      - Stage 3 handler output

set -uo pipefail

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=lib/common.sh
source "$COMMON_DIR/common.sh"

EXIT_OK=0
EXIT_ERROR=1
EXIT_UNREACHABLE=2
EXIT_NO_OPEN=3

usage() {
    echo "Usage: $0 <target>"
    echo "Example: $0 10.0.2.15"
    echo "Root is recommended for OS detection: sudo $0 10.0.2.15"
}

diag() {
    # Never silently discard diagnostic information: echo to the operator
    # and append to the per-run diagnostics log.
    local msg="${1:-}"
    echo "[!] $msg" >&2
    {
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg"
    } >> "${DIAG_LOG:-/dev/null}" 2>/dev/null || true
}

# run_bounded <seconds> <cmd...> - wraps a command in `timeout` when present.
# Returns 124 on timeout. Without `timeout` it runs unbounded and notes it.
run_bounded() {
    local tmo="$1"
    shift
    local rc=0
    if command -v timeout >/dev/null 2>&1; then
        timeout --kill-after=10s "$tmo" "$@" || rc=$?
    else
        "$@" || rc=$?
        if (( rc != 0 )); then
            diag "'timeout' is not available; command was not time-bounded."
        fi
    fi
    return "$rc"
}

# resolve_port_mode - sets PORT_MODE / PORT_ARGS / PORT_MODE_LABEL.
resolve_port_mode() {
    PORT_MODE="${ENUM_PORT_MODE_ENV:-}"
    if [[ -z "$PORT_MODE" ]]; then
        if (( NMAP_PORTS_ENV_SET == 1 )); then
            PORT_MODE="custom"
        else
            PORT_MODE="${ENUM_PORT_MODE:-top}"
        fi
    fi

    case "$PORT_MODE" in
        all)
            PORT_ARGS=( -p- )
            PORT_MODE_LABEL="all TCP ports"
            ;;
        custom)
            # intentional word splitting of "-p 22,80,443" / "-p 22-1024"
            # shellcheck disable=SC2206
            PORT_ARGS=( $NMAP_PORTS )
            [[ ${#PORT_ARGS[@]} -gt 0 ]] || PORT_ARGS=( -p- )
            PORT_MODE_LABEL="${NMAP_PORTS:-all TCP ports}"
            ;;
        top)
            if [[ ! "$ENUM_TOP_PORTS" =~ ^[0-9]+$ ]] || (( ENUM_TOP_PORTS < 1 )); then
                diag "ENUM_TOP_PORTS='$ENUM_TOP_PORTS' is not a positive integer; using 100."
                ENUM_TOP_PORTS=100
            fi
            PORT_ARGS=( --top-ports "$ENUM_TOP_PORTS" )
            PORT_MODE_LABEL="top ${ENUM_TOP_PORTS} TCP ports"
            ;;
        *)
            diag "Unknown ENUM_PORT_MODE '$PORT_MODE' - falling back to top-100."
            PORT_MODE="top"
            PORT_ARGS=( --top-ports "${ENUM_TOP_PORTS:-100}" )
            PORT_MODE_LABEL="top ${ENUM_TOP_PORTS:-100} TCP ports"
            ;;
    esac
}

# extract_open_ports <xml> <txt> -> comma-separated open TCP ports.
# Prefers the XML artifact (Python stdlib ET); falls back to the text output.
extract_open_ports() {
    local xml="${1:-}" txt="${2:-}" ports=""
    if [[ -f "$xml" ]] && sat_require python3; then
        ports="$(python3 - "$xml" 2>>"$DIAG_LOG" <<'PY' || true
import sys
import xml.etree.ElementTree as ET

try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception as exc:  # noqa: BLE001 - reported, fall back to text
    sys.stderr.write("[-] Stage-1 XML parse failed: %s\n" % exc)
    sys.exit(1)

ports = []
for host in root.findall('host'):
    for port in host.findall('ports/port'):
        state = port.find('state')
        if state is not None and state.get('state') == 'open':
            pid = port.get('portid')
            if pid and pid not in ports:
                ports.append(pid)
print(','.join(ports))
PY
)"
    fi
    if [[ -z "$ports" && -f "$txt" ]]; then
        ports="$(grep -E '^[0-9]+/[a-z]+[[:space:]]+open' "$txt" 2>/dev/null \
            | awk '{ n=split($1,a,"/"); if (!seen[a[1]]++) { printf "%s%s", (c++?",":""), a[1] } }' || true)"
    fi
    printf '%s' "$ports"
}

# extract_services <xml> <txt> <tsv> <txtout>
# Parses the Stage-2 Nmap XML (Python stdlib). On malformed XML it returns
# non-zero so the caller falls back to the text artifact; it never deletes
# the (possibly partial) XML.
extract_services() {
    local xml="$1" tsv="$2" stxt="$3"
    if [[ -f "$xml" ]] && sat_require python3; then
        python3 - "$xml" "$tsv" "$stxt" <<'PY' && return 0
import sys
import xml.etree.ElementTree as ET

xml_path, tsv_path, txt_path = sys.argv[1:4]
try:
    root = ET.parse(xml_path).getroot()
except Exception as exc:  # noqa: BLE001 - reported, caller falls back
    sys.stderr.write("[-] Stage-2 XML parse failed: %s\n" % exc)
    sys.exit(1)

services = []
for host in root.findall('host'):
    address = host.find('address')
    ip = address.get('addr', '') if address is not None else ''
    ports_node = host.find('ports')
    if ports_node is None:
        continue
    for port in ports_node.findall('port'):
        state_el = port.find('state')
        if state_el is None or state_el.get('state') != 'open':
            continue
        svc = port.find('service')
        service = product = version = extra = info = ''
        cpes = []
        if svc is not None:
            service = svc.get('name', '')
            product = svc.get('product', '')
            version = svc.get('version', '')
            extra = svc.get('extrainfo', '')
            for cpe in svc.findall('cpe'):
                if cpe.text:
                    cpes.append(cpe.text.strip())
            # join NSE script outputs (banner habits etc.) for humans
            for sc in svc.findall('script'):
                if sc.get('output'):
                    info += '[%s] %s ' % (sc.get('id', ''), sc.get('output', ''))
        services.append({
            'ip': ip,
            'port': port.get('portid', ''),
            'proto': port.get('protocol', ''),
            'service': service,
            'product': product,
            'version': version,
            'extra': extra,
            'info': info.strip(),
            'cpe': ';'.join(sorted(set(cpes))),
        })

with open(tsv_path, 'w', encoding='utf-8') as f:
    f.write('index\tip\tport\tprotocol\tservice\tproduct\tversion\textrainfo\tinfo\tcpe\n')
    for i, s in enumerate(services, start=1):
        f.write('\t'.join([
            str(i), s['ip'], s['port'], s['proto'], s['service'],
            s['product'], s['version'], s['extra'], s['info'], s['cpe'],
        ]) + '\n')

with open(txt_path, 'w', encoding='utf-8') as f:
    f.write("# Services extracted from Nmap XML (%s)\n" % xml_path)
    f.write("# port/protocol\tservice\tproduct\tversion\textrainfo\tcpe\n")
    for s in services:
        f.write("%s/%s\t%s\t%s\t%s\t%s\t%s\n" % (
            s['port'], s['proto'], s['service'], s['product'],
            s['version'], s['extra'], s['cpe']))
    f.write("# Total open ports: %d\n" % len(services))
PY
    fi
    return 1
}

# extract_services_txt_fallback <txt> <tsv> <txtout>
# Best-effort parse of the nmap text artifact (used when the XML is missing
# or malformed, or python3 is unavailable).
extract_services_txt_fallback() {
    local txt="$1" tsv="$2" stxt="$3"
    : > "$tsv"
    printf 'index\tip\tport\tprotocol\tservice\tproduct\tversion\textrainfo\tinfo\tcpe\n' >> "$tsv"
    : > "$stxt"
    echo "# Services parsed from Nmap text output (XML unavailable/unparseable): $txt" >> "$stxt"

    local i=0 p proto state svc product version rest line
    if [[ ! -f "$txt" ]]; then
        return 0
    fi
    while IFS= read -r line; do
        p="$(awk '{print $1}' <<<"$line")"
        state="$(awk '{print $2}' <<<"$line")"
        [[ -n "$p" && "$state" == "open" ]] || continue
        port="${p%%/*}"
        proto="${p##*/}"
        svc="$(awk '{print $3}' <<<"$line")"
        rest="$(awk '{for(i=4;i<=NF;i++) printf "%s%s", sep, $i; sep=" "}' sep="" <<<"$line")"
        product="$(awk '{print $1}' <<<"$rest")"
        version="$(awk '{for(i=2;i<=NF;i++) printf "%s%s", sep, $i; sep=" "}' sep="" <<<"$rest")"
        i=$((i + 1))
        printf '%s\t\t%s\t%s\t%s\t%s\t%s\t\t%s\t\n' \
            "$i" "$port" "$proto" "${svc:-unknown}" "$product" "$version" \
            "${product}${version:+ ${version}}" >> "$tsv"
        printf '%s/%s\t%s\t%s\t%s\n' "$port" "$proto" "${svc:-unknown}" "$product" "$version" >> "$stxt"
    done < <(grep -E '^[0-9]+/[a-z]+[[:space:]]+open' "$txt" || true)
    echo "# Total open ports: $i" >> "$stxt"

    # Rows might be empty here only when the file has data the simple parser
    # cannot decode; never claim success silently - the caller is told.
    printf 'count=%d\n' "$i"
}

# write_ports_artifacts <base> <src_txt> - preserves Stage-1 discovery data.
write_ports_artifacts() {
    local base="$1" src_txt="$2"
    {
        echo "# Port discovery (Stage 1) - security-assessment"
        echo "# target=$TARGET"
        echo "# port_mode=$PORT_MODE ($PORT_MODE_LABEL)"
        echo "# source_txt=$src_txt"
        echo "# status=$STAGE1_STATUS"
        echo "# wrapper_exit=$STAGE1_WRAPPER_RC"
        echo "# open_tcp_ports=${OPEN_PORTS:-none}"
        echo
        echo "${OPEN_PORTS:-}"
        echo
        if [[ -f "$src_txt" ]]; then
            echo "# raw open lines (diagnostic, from $src_txt):"
            grep -E '^[0-9]+/[a-z]+[[:space:]]+open' "$src_txt" || true
        fi
    } > "${base}.ports.txt"

    local rows="" seen=0 line p
    if [[ -f "$src_txt" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^([0-9]+)/([a-z]+)[[:space:]]+open ]]; then
                rows+="${BASH_REMATCH[1]}"$'\t'"${BASH_REMATCH[2]}"$'\topen\n'
                seen=1
            fi
        done < <(grep -E '^[0-9]+/[a-z]+[[:space:]]+open' "$src_txt" || true)
    fi
    if (( seen == 0 )); then
        for p in ${OPEN_PORTS//,/ }; do
            [[ -n "$p" ]] && rows+="${p}"$'\ttcp\topen\n'
        done
    fi
    { printf 'port\tprotocol\tstate\n'; printf '%s' "$rows"; } > "${base}.ports.tsv"
}

# run_stage3 <stage2_xml> <services_tsv> - dispatch service handlers.
run_stage3() {
    local xml="${1:-}" tsv="$2"
    local stage3="$STAGE3_DIR"
    mkdir -p "$stage3"
    : > "$stage3/handlers.tsv"
    printf 'port\tprotocol\tservice\tproduct\tversion\thandler\tstatus\trc\tnote\n' > "$stage3/handlers.tsv"

    HANDLER_DIR="$PROJECT_ROOT/modules/service_handlers"
    if [[ ! -d "$HANDLER_DIR" ]]; then
        STAGE3_STATUS="no-handlers-dir"
        return 0
    fi

    local ran=0 err=0 handled=0
    local ports_list
    ports_list="$(tail -n +2 "$tsv" 2>/dev/null || true)"
    if [[ -z "$ports_list" ]]; then
        STAGE3_STATUS="no-services"
        return 0
    fi

    local idx ip port proto service product version extra info cpe
    while IFS=$'\t' read -r idx ip port proto service product version extra info cpe; do
        [[ -n "$port" ]] || continue
        local h hstatus hrc=0 hnote="" handles="" tok match
        for h in "$HANDLER_DIR"/*_handler.sh; do
                [[ -f "$h" ]] || continue
                handles="$(sed -n 's/^HANDLES=[[:space:]]*//p' "$h" 2>/dev/null | head -n1 | tr -d '"' | tr -d "'")"
                handles="${handles:-*}"
                match=0
                if [[ "$handles" == "*" || "$handles" == "all" ]]; then
                    match=1
                else
                    for tok in $handles; do
                        if [[ "$service" == "$tok" || "$service" == "$tok-"* ]]; then
                            match=1
                            break
                        fi
                    done
                fi
                (( match == 1 )) || continue
                handled=$((handled + 1))

                local hdir="$stage3/${port}_${service}"
                mkdir -p "$hdir"
                if command -v timeout >/dev/null 2>&1; then
                    timeout --kill-after=5s "$ENUM_HANDLER_TIMEOUT" \
                        bash "$h" "$xml" "$TARGET" "$port" "$proto" \
                             "$service" "$product" "$version" "$hdir" \
                        2>>"$stage3/handlers.err" || hrc=$?
                else
                    bash "$h" "$xml" "$TARGET" "$port" "$proto" \
                         "$service" "$product" "$version" "$hdir" \
                        2>>"$stage3/handlers.err" || hrc=$?
                fi
                ran=$((ran + 1))

            hstatus="ok"
            if (( hrc == 124 )); then
                hstatus="timeout"
                hnote="handler exceeded ${ENUM_HANDLER_TIMEOUT}s"
                err=$((err + 1))
            elif (( hrc != 0 )); then
                hstatus="error"
                hnote="handler exited $hrc"
                err=$((err + 1))
            elif [[ -f "$hdir/status.txt" ]]; then
                hstatus="$(grep -E '^status=' "$hdir/status.txt" 2>/dev/null | head -n1 | cut -d= -f2-)"
                hstatus="${hstatus:-ok}"
                if [[ "$hstatus" == "error"* ]]; then
                    err=$((err + 1))
                fi
            fi
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$port" "$proto" "$service" "$product" "$version" \
                "$(basename "$h")" "$hstatus" "$hrc" "$hnote" >> "$stage3/handlers.tsv"
        done
    done <<< "$ports_list"

    STAGE3_STATUS="ok"
    (( ran == 0 )) && STAGE3_STATUS="no-handlers-ran"
    (( err > 0 )) && STAGE3_STATUS="warning"
    return 0
}

# ---------------------------------------------------------------
# main
# ---------------------------------------------------------------

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    usage
    exit "$EXIT_ERROR"
fi
if ! sat_validate_target "$TARGET"; then
    echo "[-] Invalid target value: '$TARGET'" >&2
    usage
    exit "$EXIT_ERROR"
fi

# Capture env-only overrides BEFORE configuration is loaded so an explicit
# NMAP_PORTS continues to behave as a custom port range (backward compat).
NMAP_PORTS_ENV_SET=0
if [[ "${NMAP_PORTS+set}" == "set" ]]; then
    NMAP_PORTS_ENV_SET=1
fi
ENUM_PORT_MODE_ENV=""
if [[ "${ENUM_PORT_MODE+set}" == "set" ]]; then
    ENUM_PORT_MODE_ENV="$ENUM_PORT_MODE"
fi

sat_load_config || exit "$EXIT_ERROR"
sat_apply_defaults
resolve_port_mode

# Compute the output paths early so diagnostics can be recorded even when a
# required tool is missing (never silent).
OUTPUT_DIR="${OUTPUT_ENUM:-$PROJECT_ROOT/output/enumeration}"
if ! mkdir -p "$OUTPUT_DIR"; then
    echo "[-] Could not create output directory: $OUTPUT_DIR" >&2
    exit "$EXIT_ERROR"
fi

SAFE_TARGET="$(sat_safe_name "$TARGET")"
TIMESTAMP="$(sat_timestamp)"
OUTPUT_BASE="$OUTPUT_DIR/${SAFE_TARGET}_${TIMESTAMP}"

PORTS_TXT="$OUTPUT_BASE.ports.txt"
PORTS_RAW="$OUTPUT_BASE.ports.nmap.txt"
PORTS_TSV="$OUTPUT_BASE.ports.tsv"
PORTS_XML="$OUTPUT_BASE.ports.xml"
ENUM_TXT="$OUTPUT_BASE.txt"
ENUM_XML="$OUTPUT_BASE.xml"
SERVICES_TSV="$OUTPUT_BASE.services.tsv"
SERVICES_TXT="$OUTPUT_BASE.services.txt"
STATUS_FILE="$OUTPUT_BASE.status.txt"
DIAG_LOG="$OUTPUT_BASE.diagnostics.log"
STAGE3_DIR="$OUTPUT_BASE.stage3"
: > "$DIAG_LOG" 2>/dev/null || true

if ! sat_require nmap; then
    diag "nmap is not installed (required for all enumeration stages)."
    exit "$EXIT_ERROR"
fi

OS_DETECTION=0
SCAN_TYPE="-sT"
if [[ $EUID -eq 0 ]]; then
    OS_DETECTION=1
    SCAN_TYPE="-sS"
fi

echo "========================================"
echo "       SERVICE ENUMERATION (V2)"
echo "========================================"
echo
echo "[*] Target:      $TARGET"
echo "[*] Port mode:   $PORT_MODE ($PORT_MODE_LABEL)"
echo "[*] Timing:      $NMAP_TIMING"
echo "[*] Detection:   $NMAP_SERVICE_DETECTION"
echo "[*] NSE scripts: $NMAP_SCRIPTS"
if (( OS_DETECTION == 1 )); then
    echo "[+] Running as root - OS detection (-O) ENABLED on Stage 2."
else
    echo "[!] Not running as root - OS detection (-O) skipped."
    echo "    Re-run as: sudo $0 $TARGET"
fi
echo

# ---------------------------------------------------------------
# Stage 1 - Port discovery
# ---------------------------------------------------------------
echo "######## STAGE 1 - PORT DISCOVERY ########"
echo

STAGE1_STATUS="not-run"
STAGE1_WRAPPER_RC=0
STAGE1_RESULT=""
OPEN_PORTS=""
CLOSED_CNT=0

STAGE1_CMD=( nmap "$NMAP_TIMING" -Pn -n -sT --max-retries 1
             "${PORT_ARGS[@]}" "$TARGET"
             -oN "$PORTS_RAW" -oX "$PORTS_XML" )
echo "[*] Running port discovery:"
echo "    ${STAGE1_CMD[*]}"
echo
run_bounded "$ENUM_DISCOVERY_TIMEOUT" "${STAGE1_CMD[@]}" || STAGE1_WRAPPER_RC=$?

if (( STAGE1_WRAPPER_RC == 124 )); then
    STAGE1_STATUS="timeout"
    diag "Stage-1 port discovery hit the ${ENUM_DISCOVERY_TIMEOUT}s timeout."
elif (( STAGE1_WRAPPER_RC != 0 )); then
    STAGE1_STATUS="error"
    diag "Stage-1 nmap exited code $STAGE1_WRAPPER_RC."
else
    STAGE1_STATUS="ok"
fi

OPEN_PORTS="$(extract_open_ports "$PORTS_XML" "$PORTS_RAW")"
if [[ -f "$PORTS_RAW" ]]; then
    CLOSED_CNT="$(grep -cE '^[0-9]+/[a-z]+[[:space:]]+closed' "$PORTS_RAW" || true)"
    CLOSED_CNT="${CLOSED_CNT:-0}"
fi

write_ports_artifacts "$OUTPUT_BASE" "$PORTS_RAW"

echo
echo "[*] Stage-1 result:"
echo "    status:            $STAGE1_STATUS"
echo "    open TCP ports:    ${OPEN_PORTS:-none}"
echo "    closed (host up?): ${CLOSED_CNT:-0}"
echo "    artifacts:"
echo "      $PORTS_RAW"
echo "      $PORTS_TXT"
echo "      $PORTS_TSV"
[[ -f "$PORTS_XML" ]] && echo "      $PORTS_XML"
echo

if [[ -n "$OPEN_PORTS" ]]; then
    STAGE1_RESULT="proceed"
    echo "[+] Host reachable - discovered open TCP port(s): $OPEN_PORTS"
elif (( CLOSED_CNT > 0 )); then
    STAGE1_RESULT="no-open"
    echo "[!] Host reachable but no open TCP services were found."
elif [[ -f "$PORTS_RAW" && "$STAGE1_STATUS" == "ok" ]]; then
    STAGE1_RESULT="unreachable"
    echo "[-] No TCP responses were received - the host did not reply to any scanned port."
else
    STAGE1_RESULT="error"
    echo "[-] Stage-1 port discovery failed and produced no usable output." >&2
fi

if [[ "$STAGE1_RESULT" != "proceed" ]]; then
    status=""
    case "$STAGE1_RESULT" in
        no-open)      status="completed-no-open-ports" ;;
        unreachable)  status="unreachable" ;;
        *)            status="error" ;;
    esac
    {
        echo "status=$status"
        echo "stage1_status=$STAGE1_STATUS"
        echo "stage1_wrapper_exit=$STAGE1_WRAPPER_RC"
        echo "target=$TARGET"
        echo "port_mode=$PORT_MODE ($PORT_MODE_LABEL)"
        echo "timestamp=$TIMESTAMP"
        echo "ports_txt=$(basename "$PORTS_TXT")"
        echo "ports_nmap_txt=$(basename "$PORTS_RAW")"
        echo "ports_tsv=$(basename "$PORTS_TSV")"
        echo "ports_xml=$(basename "$PORTS_XML")"
        echo "open_tcp_ports=${OPEN_PORTS:-none}"
    } > "$STATUS_FILE"

    echo
    echo "[-] Output directory: $OUTPUT_DIR"
    echo

    if [[ "$STAGE1_RESULT" == "unreachable" ]]; then
        echo "[-] TARGET UNREACHABLE: $TARGET"
        echo "    The expensive service scan was skipped."
        echo "    Possible causes: wrong target IP, wrong network adapter,"
        echo "    or no route from this host to the target subnet."
        echo "    Diagnostic output preserved in:"
        echo "      $PORTS_RAW"
        echo "      $DIAG_LOG"
        exit "$EXIT_UNREACHABLE"
    fi
    if [[ "$STAGE1_RESULT" == "no-open" ]]; then
        echo "[!] Stage-1 completed cleanly: host up, zero open TCP ports."
        echo "    This is a valid evidence-based result (see $STATUS_FILE)."
        exit "$EXIT_NO_OPEN"
    fi
    echo "[-] Enumeration could not continue - see $DIAG_LOG" >&2
    exit "$EXIT_ERROR"
fi

# ---------------------------------------------------------------
# Stage 2 - Targeted service enumeration (discovered ports only)
# ---------------------------------------------------------------
echo
echo "######## STAGE 2 - TARGETED SERVICE ENUMERATION ########"
echo

STAGE2_STATUS="not-run"
STAGE2_WRAPPER_RC=0
SERVICES_COUNT=0
SERVICES_PARSE="not-run"

STAGE2_CMD=( nmap "$NMAP_TIMING" "$NMAP_SERVICE_DETECTION" "--script=${NMAP_SCRIPTS:-default}"
             -Pn -n -p "$OPEN_PORTS" "$TARGET"
             -oN "$ENUM_TXT" -oX "$ENUM_XML" )
if (( OS_DETECTION == 1 )); then
    STAGE2_CMD+=( -O )
fi
echo "[*] Running targeted service scan (only discovered ports $OPEN_PORTS):"
echo "    ${STAGE2_CMD[*]}"
echo
run_bounded "$ENUM_SERVICE_TIMEOUT" "${STAGE2_CMD[@]}" || STAGE2_WRAPPER_RC=$?

if (( STAGE2_WRAPPER_RC == 124 )); then
    STAGE2_STATUS="timeout"
    diag "Stage-2 service scan hit the ${ENUM_SERVICE_TIMEOUT}s timeout."
elif (( STAGE2_WRAPPER_RC != 0 )); then
    STAGE2_STATUS="error"
    diag "Stage-2 nmap exited code $STAGE2_WRAPPER_RC - parsing whatever output exists."
else
    STAGE2_STATUS="ok"
fi

# Parse the XML (Python stdlib); fall back to the text artifact on
# malformed/truncated XML or a missing python3.
if extract_services "$ENUM_XML" "$SERVICES_TSV" "$SERVICES_TXT"; then
    SERVICES_PARSE="xml"
    if [[ ! -s "$SERVICES_TSV" ]]; then
        SERVICES_PARSE="xml-empty"
    fi
else
    SERVICES_PARSE="txt-fallback"
    diag "Stage-2 XML unavailable/unparseable - parsed the text artifact."
    extract_services_txt_fallback "$ENUM_TXT" "$SERVICES_TSV" "$SERVICES_TXT" || true
fi

if [[ -f "$SERVICES_TXT" ]]; then
    SERVICES_COUNT="$(sed -n 's/^# Total open ports: //p' "$SERVICES_TXT" | head -n1 || true)"
    SERVICES_COUNT="${SERVICES_COUNT:-0}"
fi
[[ "$SERVICES_COUNT" =~ ^[0-9]+$ ]] || SERVICES_COUNT=0

echo
echo "[*] Stage-2 result:"
echo "    status:         $STAGE2_STATUS"
echo "    parse:          $SERVICES_PARSE"
echo "    services:       $SERVICES_COUNT"
echo "    nmap exit:      $STAGE2_WRAPPER_RC"
echo "    artifacts:"
echo "      $ENUM_TXT"
[[ -f "$ENUM_XML" ]] && echo "      $ENUM_XML"
echo "      $SERVICES_TSV"
echo "      $SERVICES_TXT"
echo

# ---------------------------------------------------------------
# Stage 3 - Service-specific enumeration (modular, read-only)
# ---------------------------------------------------------------
echo "######## STAGE 3 - SERVICE-SPECIFIC ENUMERATION ########"
echo
STAGE3_STATUS="none"
if [[ -f "$SERVICES_TSV" ]]; then
    run_stage3 "$ENUM_XML" "$SERVICES_TSV"
    echo "[*] Stage-3 status: $STAGE3_STATUS"
    echo "    artifacts:"
    echo "      $STAGE3_DIR/handlers.tsv"
    echo
else
    diag "Stage-3 skipped - no services.tsv to dispatch on."
fi

# ---------------------------------------------------------------
# Classification + status
# ---------------------------------------------------------------
echo "[*] Classification of results..."
if (( SERVICES_COUNT > 0 )); then
    echo "[+] OPEN SERVICES DISCOVERED ($SERVICES_COUNT)"
    if [[ -f "$SERVICES_TXT" ]]; then
        sed -n '1,40p' "$SERVICES_TXT" | sed 's/^/    /'
    fi
else
    echo "[!] Open TCP ports were found (${OPEN_PORTS}) but no service data was parsed."
    echo "    This is preserved as status=partial - see $STATUS_FILE."
fi
echo

STATUS_VALUE="completed"
if [[ "$STAGE2_STATUS" == "ok" && "$SERVICES_PARSE" == "xml" ]]; then
    STATUS_VALUE="completed"
else
    STATUS_VALUE="partial"
fi
case "$STAGE2_STATUS" in
    timeout) STATUS_VALUE="partial-timeout" ;;
    error)   STATUS_VALUE="partial-scan-error" ;;
esac
if (( SERVICES_COUNT == 0 )); then
    STATUS_VALUE="partial-no-parsed-services"
fi

{
    echo "status=$STATUS_VALUE"
    echo "target=$TARGET"
    echo "timestamp=$TIMESTAMP"
    echo "port_mode=$PORT_MODE ($PORT_MODE_LABEL)"
    echo "stage1_status=$STAGE1_STATUS"
    echo "stage1_wrapper_exit=$STAGE1_WRAPPER_RC"
    echo "stage2_status=$STAGE2_STATUS"
    echo "stage2_wrapper_exit=$STAGE2_WRAPPER_RC"
    echo "stage2_parse=$SERVICES_PARSE"
    echo "open_tcp_ports=$OPEN_PORTS"
    echo "services=$SERVICES_COUNT"
    echo "ports_txt=$(basename "$PORTS_TXT")"
    echo "ports_nmap_txt=$(basename "$PORTS_RAW")"
    echo "ports_tsv=$(basename "$PORTS_TSV")"
    echo "ports_xml=$(basename "$PORTS_XML")"
    echo "enumeration_txt=$(basename "$ENUM_TXT")"
    echo "enumeration_xml=$(basename "$ENUM_XML")"
    echo "services_tsv=$(basename "$SERVICES_TSV")"
    echo "services_txt=$(basename "$SERVICES_TXT")"
    echo "stage3_status=$STAGE3_STATUS"
    echo "diagnostics_log=$(basename "$DIAG_LOG")"
} > "$STATUS_FILE"

echo "[-] Output directory: $OUTPUT_DIR"
echo "    Status: $STATUS_VALUE"
echo "    Status file: $STATUS_FILE"
echo
exit "$EXIT_OK"