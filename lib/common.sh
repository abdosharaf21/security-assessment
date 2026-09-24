#!/usr/bin/env bash
#
# Common helpers shared by security-assessment modules.
# Source this file, do not execute it directly.
#
# Provides:
#   sat_require, sat_check_cmd
#   sat_load_config, sat_apply_defaults
#   sat_safe_name, sat_timestamp
#   sat_latest_file, sat_latest_dir
#   sat_validate_target, sat_require_python3

if [[ -n "${SAT_COMMON_LOADED:-}" ]]; then
    return 0
fi
SAT_COMMON_LOADED=1

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$COMMON_DIR/.." && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$PROJECT_ROOT/config/config.conf}"

# Output locations (architectural, mirrored in config where relevant)
OUTPUT_ROOT="$PROJECT_ROOT/output"
OUTPUT_NMAP="${OUTPUT_NMAP:-$OUTPUT_ROOT/nmap}"
OUTPUT_ENUM="${OUTPUT_ENUM:-$OUTPUT_ROOT/enumeration}"
OUTPUT_VULN="${OUTPUT_VULN:-$OUTPUT_ROOT/vulnerabilities}"
OUTPUT_EXPLOIT="${OUTPUT_EXPLOIT:-$OUTPUT_ROOT/exploitation}"
OUTPUT_EVIDENCE="${OUTPUT_EVIDENCE:-$OUTPUT_ROOT/evidence}"
OUTPUT_REPORTS="${OUTPUT_REPORTS:-$PROJECT_ROOT/reports}"
OUTPUT_COMPARE="${OUTPUT_COMPARE:-$OUTPUT_ROOT/comparisons}"
EXPLOIT_MAPPING_FILE="${EXPLOIT_MAPPING_FILE:-$PROJECT_ROOT/config/exploit_mapping.conf}"

# Exit codes shared across later phases
EXIT_OK=0          # success
EXIT_ERROR=1       # usage/config/technical error
EXIT_NO_DATA=2     # ran cleanly but produced/consumed no relevant data
EXIT_DEPENDENCY=3  # required external tool missing

# ---------------------------------------------------------------
# Dependency helpers
# ---------------------------------------------------------------

sat_require() {
    local tool="$1"
    command -v "$tool" >/dev/null 2>&1
}

sat_check_cmd() {
    local tool="$1"
    if sat_require "$tool"; then
        echo "[+] $tool: OK"
        return 0
    fi
    echo "[!] $tool: NOT FOUND"
    return 1
}

sat_require_python3() {
    if sat_require python3; then
        return 0
    fi
    echo "[-] python3 is required for this phase but is not installed." >&2
    return 1
}

# ---------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------

# config.conf -> exported shell variables.
# Environment variables always win over config.conf.
sat_load_config() {
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

sat_apply_defaults() {
    NMAP_TIMING="${NMAP_TIMING:--T4}"
    NMAP_PORTS="${NMAP_PORTS:--p-}"
    NMAP_SERVICE_DETECTION="${NMAP_SERVICE_DETECTION:--sV}"
    # Safe default: the 'default' NSE category only. No 'vuln' category
    # and no exploitation is ever run automatically. Vulnerability
    # detection stays in Phase 3 (SearchSploit) - a separate concern.
    NMAP_SCRIPTS="${NMAP_SCRIPTS:-default}"
    NMAP_OUTPUT_FORMAT="${NMAP_OUTPUT_FORMAT:-xml}"

    # Phase 2 (Enumeration V2) - multi-stage port selection
    #   ENUM_PORT_MODE=top    top-N TCP ports (N = ENUM_TOP_PORTS, default 100)
    #   ENUM_PORT_MODE=all    all 65535 TCP ports (-p-)
    #   ENUM_PORT_MODE=custom NMAP_PORTS (-p <list/range>)
    # An explicitly exported NMAP_PORTS is always honored as 'custom' for
    # backward compatibility with existing callers.
    ENUM_PORT_MODE="${ENUM_PORT_MODE:-top}"
    ENUM_TOP_PORTS="${ENUM_TOP_PORTS:-100}"
    ENUM_DISCOVERY_TIMEOUT="${ENUM_DISCOVERY_TIMEOUT:-300}"
    ENUM_SERVICE_TIMEOUT="${ENUM_SERVICE_TIMEOUT:-600}"
    ENUM_HANDLER_TIMEOUT="${ENUM_HANDLER_TIMEOUT:-30}"

    SEARCHSPLOIT_ENABLED="${SEARCHSPLOIT_ENABLED:-true}"
    METASPLOIT_ENABLED="${METASPLOIT_ENABLED:-true}"
    AUTO_EXPLOIT="${AUTO_EXPLOIT:-false}"
    REQUIRE_EXPLOIT_APPROVAL="${REQUIRE_EXPLOIT_APPROVAL:-true}"
    REPORT_FORMAT="${REPORT_FORMAT:-md,html}"
    REPORT_TITLE="${REPORT_TITLE:-Metasploitable 2 Security Assessment}"

    # Scope / incremental assessment (Phases 10-11)
    ENUMERATION_WORKERS="${ENUMERATION_WORKERS:-2}"
    SCOPE_TARGET_TIMEOUT="${SCOPE_TARGET_TIMEOUT:-300}"
    SCOPE_MAX_EXPANDED_TARGETS="${SCOPE_MAX_EXPANDED_TARGETS:-256}"
}

sat_config_bool() {
    # sat_config_bool <value> -> 0 if the value means true, else 1
    case "$(printf '%s' "${1:-false}" | tr '[:upper:]' '[:lower:]')" in
        true|1|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------
# Naming / time
# ---------------------------------------------------------------

sat_safe_name() {
    printf '%s' "${1//[^a-zA-Z0-9_.-]/_}"
}

sat_timestamp() {
    # Nanosecond resolution avoids colliding artifact dirs when several
    # phases run inside the same wall-clock second.
    date '+%Y%m%d_%H%M%S%N' 2>/dev/null || date '+%Y%m%d_%H%M%S'
}

# ---------------------------------------------------------------
# Artifact discovery (lexicographic ordering == chronological here)
# ---------------------------------------------------------------

sat_latest_file() {
    # $1: glob pattern. Prints the lexically-latest matching regular file.
    local pattern="$1" f latest=""
    for f in $pattern; do
        [[ -f "$f" ]] || continue
        latest="$f"
    done
    printf '%s' "$latest"
}

sat_latest_dir() {
    # $1: base dir, $2: prefix. Prints the lexically-latest matching directory.
    local base="$1" prefix="$2" d latest=""
    [[ -d "$base" ]] || { printf ''; return; }
    for d in "$base"/"${prefix}"_*; do
        [[ -d "$d" ]] || continue
        latest="$d"
    done
    printf '%s' "$latest"
}

sat_latest_dir_with() {
    # $1: base dir, $2: prefix, $3: marker file that must exist inside the dir.
    # Prints the lexically-latest directory that contains the marker file.
    local base="$1" prefix="$2" marker="$3" d latest=""
    [[ -d "$base" ]] || { printf ''; return; }
    for d in "$base"/"${prefix}"_*; do
        [[ -d "$d" ]] || continue
        [[ -f "$d/$marker" ]] || continue
        latest="$d"
    done
    printf '%s' "$latest"
}

# ---------------------------------------------------------------
# Enumeration V2 artifact selection
# ---------------------------------------------------------------
#
# Enumeration V2 writes two XML/text artifact families for one run:
#   base.ports.xml / base.ports.txt   - Stage 1 port discovery (no versions)
#   base.xml       / base.txt         - Stage 2 targeted service enumeration
# and records the authoritative Stage-2 names in base.status.txt as
#   enumeration_xml=<basename>  /  enumeration_txt=<basename>
#
# Selecting "the enumeration artifact" by filename glob is unsafe: the
# Stage-1 ".ports.xml" name sorts before the Stage-2 ".xml" name, and a
# partially-quoted glob can even be pre-expanded by the shell. These helpers
# therefore read the run's recorded state (status.txt) and only fall back to
# an mtime-ordered scan for status-less legacy artifacts. The Stage-1
# ".ports.*" family is never returned.

sat_enum_service_xml() {
    # sat_enum_service_xml <enum_dir> <safe_target>
    # Prints the absolute path of the newest run's Stage-2 service XML, or
    # nothing when no Stage-2 XML exists.
    local base="${1:-}" prefix="${2:-}" s f val sts best="" best_ts=""
    [[ -n "$base" && -n "$prefix" && -d "$base" ]] || { printf ''; return 0; }

    for s in "$base/${prefix}_"*.status.txt; do
        [[ -f "$s" ]] || continue
        val="$(sed -n 's/^enumeration_xml=//p' "$s" | head -n1)"
        [[ -n "$val" ]] || continue
        case "$val" in *.ports.xml) continue ;; esac
        [[ -f "$base/$val" ]] || continue
        sts="$(sed -n 's/^timestamp=//p' "$s" | head -n1)"
        [[ -n "$sts" ]] || sts="$(basename "$s")"
        if [[ -z "$best_ts" || "$sts" > "$best_ts" ]]; then
            best="$base/$val"
            best_ts="$sts"
        fi
    done
    if [[ -z "$best" ]]; then
        # Backward compatibility: status-less/legacy runs. Pick the newest
        # non-Stage-1 XML by modification time (never lexical order).
        for f in "$base/${prefix}_"*.xml; do
            [[ -f "$f" ]] || continue
            case "$f" in *.ports.xml) continue ;; esac
            if [[ -z "$best" || "$f" -nt "$best" ]]; then
                best="$f"
            fi
        done
    fi
    printf '%s' "$best"
}

sat_enum_service_txt() {
    # sat_enum_service_txt <enum_dir> <safe_target>
    # Prints the absolute path of the newest run's Stage-2 enumeration text,
    # or nothing when it does not exist.
    local base="${1:-}" prefix="${2:-}" s val sts best="" best_ts="" xml
    [[ -n "$base" && -n "$prefix" && -d "$base" ]] || { printf ''; return 0; }

    for s in "$base/${prefix}_"*.status.txt; do
        [[ -f "$s" ]] || continue
        val="$(sed -n 's/^enumeration_txt=//p' "$s" | head -n1)"
        [[ -n "$val" ]] || continue
        [[ -f "$base/$val" ]] || continue
        sts="$(sed -n 's/^timestamp=//p' "$s" | head -n1)"
        [[ -n "$sts" ]] || sts="$(basename "$s")"
        if [[ -z "$best_ts" || "$sts" > "$best_ts" ]]; then
            best="$base/$val"
            best_ts="$sts"
        fi
    done
    if [[ -z "$best" ]]; then
        xml="$(sat_enum_service_xml "$base" "$prefix")"
        if [[ -n "$xml" && -f "${xml%.xml}.txt" ]]; then
            best="${xml%.xml}.txt"
        fi
    fi
    printf '%s' "$best"
}

# ---------------------------------------------------------------
# Assessment-scoped enumeration artifact resolution
# ---------------------------------------------------------------
#
# Enumeration runs inside an assessment write their Stage-2 artifacts under
# output/assessments/<id>/enumeration/, which the standalone/legacy phase
# entry points would otherwise never see. sat_assessment_enum_xml closes
# that gap: it resolves the newest compatible Stage-2 enumeration service
# XML for a target across every assessment (newest assessment wins, judged
# by its nanosecond id; within one assessment sat_enum_service_xml already
# picks the newest Stage-2 run). Stage-1 ".ports.xml" artifacts are never
# returned.

sat_assessment_enum_xml() {
    # sat_assessment_enum_xml <target> -> absolute path of the newest
    # assessment-scoped Stage-2 enumeration XML for <target>, or nothing.
    local target="${1:-}" prefix root m id dir tgt xml best="" best_id=""
    prefix="$(sat_safe_name "$target")"
    root="${ASSESSMENTS_ROOT:-$OUTPUT_ROOT/assessments}"
    [[ -n "$prefix" && -d "$root" ]] || { printf ''; return 0; }
    for m in "$root"/assessment_*/manifest.json; do
        [[ -f "$m" ]] || continue
        tgt="$(python3 - "$m" 2>/dev/null <<'PY'
import json
import sys
try:
    with open(sys.argv[1]) as fh:
        print((json.load(fh).get('target') or ''))
except Exception:
    print('')
PY
)"
        [[ -n "$tgt" && "$tgt" == "$target" ]] || continue
        dir="${m%/manifest.json}/enumeration"
        [[ -d "$dir" ]] || continue
        xml="$(sat_enum_service_xml "$dir" "$prefix")"
        [[ -n "$xml" ]] || continue
        id="${m%/manifest.json}"
        if [[ -z "$best_id" || "$id" > "$best_id" ]]; then
            best="$xml"
            best_id="$id"
        fi
    done
    printf '%s' "$best"
}

# ---------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------

sat_validate_target() {
    local t="${1:-}"
    [[ -n "$t" ]] || return 1
    # No option injection / whitespace / shell metacharacters.
    case "$t" in
        -*|*[[:space:]]*|*\;*|*\&*|*\|*|*\>*|*\<*|\`*|*\$*|*\(*|*\)*|*\{*|*\}*) return 1 ;;
        *) return 0 ;;
    esac
}