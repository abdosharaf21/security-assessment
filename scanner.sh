#!/usr/bin/env bash
#
# Security Assessment Tool - main controller
#
# Unified CLI:
#   ./scanner.sh scan <target> [--quick|--full|--dry-run]
#   ./scanner.sh scan <scope_id> [--new|--failed|--all|--targets a,b,c]
#                                [--workers N] [--dry-run]   # scope scan
#   ./scanner.sh status [<assessment-id>]
#   ./scanner.sh resume <assessment-id> [--dry-run]
#   ./scanner.sh report <assessment-id>
#   ./scanner.sh scope list|create|show|status|expand ...
#   ./scanner.sh history [<assessment-id>]
#   ./scanner.sh compare <assessment-id-A> <assessment-id-B>
#   ./scanner.sh preflight [<target>]
#   ./scanner.sh menu            (interactive main menu)
#   ./scanner.sh --help
#
# Legacy phases (unchanged dispatch):
#   ./scanner.sh <target> discovery          # single phase, nothing else runs
#   ./scanner.sh <target> enumeration        # single phase
#   ./scanner.sh <target> vulnerabilities     # single phase
#   ./scanner.sh <target> correlation         # single phase
#   ./scanner.sh <target> exploit             # single phase (explicit approval only)
#   ./scanner.sh <target> evidence            # single phase
#   ./scanner.sh <target> report              # single phase
#   ./scanner.sh <target> full                # full pipeline:
#       discovery -> enumeration -> vulnerabilities -> correlation ->
#       exploitation (explicit in-run approval REQUIRED) -> evidence -> report
#   ./scanner.sh <target> all                # discovery + enumeration only
#
# Pipeline (modular phases):
#   discovery.sh    (Phase 1 - host discovery)
#   enumeration.sh  (Phase 2 - service enumeration)
#   vulnerability.sh (Phase 3 - SearchSploit research)
#   correlation.sh  (Phase 4 - finding correlation / risk)
#   exploitation.sh (Phase 5 - lab-only Metasploit exploitation)
#   evidence.sh     (Phase 6 - evidence / session handling)
#   report.sh       (Phase 7 - report generation)
#
# Phase 5 (exploitation) is STRICTLY for the authorized Metasploitable 2
# lab target, is never run automatically (scan/resume/--dry-run), and
# always requires explicit in-run selection + approval.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$PROJECT_ROOT/config/config.conf}"
MODULES_DIR="$PROJECT_ROOT/modules"

# shellcheck source=lib/common.sh
source "$PROJECT_ROOT/lib/common.sh"
# shellcheck source=lib/assessment.sh
source "$PROJECT_ROOT/lib/assessment.sh"
# shellcheck source=lib/scope.sh
source "$PROJECT_ROOT/lib/scope.sh"

print_banner() {
    echo "========================================"
    echo "      SECURITY ASSESSMENT TOOL"
    echo "      Authorized lab use only"
    echo "========================================"
    echo
}

check_dependencies() {
    local phase="${1:-all}"

    echo "[*] Checking dependencies (phase: $phase)..."

    if command -v nmap >/dev/null 2>&1; then
        echo "[+] nmap: OK"
    else
        echo "[-] nmap: NOT FOUND - required for all phases" >&2
        exit 1
    fi

    if command -v python3 >/dev/null 2>&1; then
        echo "[+] python3: OK"
    else
        echo "[!] python3: NOT FOUND - Phases 3-7 unavailable"
    fi

    if command -v searchsploit >/dev/null 2>&1; then
        echo "[+] searchsploit: OK"
    else
        echo "[!] searchsploit: NOT FOUND - Phase 3 unavailable"
    fi

    if command -v msfconsole >/dev/null 2>&1; then
        echo "[+] msfconsole: OK"
    else
        echo "[!] msfconsole: NOT FOUND - Phase 5 unavailable"
    fi

    echo
}

load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "[-] Configuration file not found:"
        echo "    $CONFIG_FILE"
        exit 1
    fi

    local key value
    while IFS='=' read -r key value; do
        key="${key//[[:space:]]/}"
        [[ -z "$key" || "$key" == \#* ]] && continue
        [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
        [[ -n "${!key:-}" ]] && continue
        value="${value%\"}"
        value="${value#\"}"
        value="${value%\'}"
        value="${value#\'}"
        export "$key=$value"
    done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$CONFIG_FILE" || true)
}

get_target() {
    local target="${1:-}"
    if [[ -z "$target" ]]; then
        read -r -p "[?] Enter target IP: " target
    fi
    if [[ -z "$target" ]]; then
        echo "[-] Target cannot be empty."
        exit 1
    fi
    sat_validate_target "$target" || {
        echo "[-] Invalid target value." >&2
        exit 1
    }
    TARGET="$target"
    echo "[+] Target: $TARGET"
    echo
}

run_phase() {
    # run_phase <label> <command...>
    local label="$1"
    shift
    local rc=0
    echo
    echo "######## PHASE: $label ########"
    echo
    "$@" || rc=$?
    if (( rc == 0 )); then
        return 0
    fi
    echo
    echo "[!] Phase '$label' finished with exit code $rc."
    return "$rc"
}

assert_module() {
    local name="$1"
    if [[ ! -x "$MODULES_DIR/$name" ]]; then
        echo "[-] $name is missing or not executable." >&2
        exit 1
    fi
}

# ---------------------------------------------------------------
# Per-phase runners (legacy, standalone)
# ---------------------------------------------------------------

phase_discovery() {
    assert_module discovery.sh
    run_phase "Discovery" "$MODULES_DIR/discovery.sh" "$TARGET"
}

phase_enumeration() {
    assert_module enumeration.sh
    run_phase "Service Enumeration" "$MODULES_DIR/enumeration.sh" "$TARGET"
}

phase_vulnerabilities() {
    assert_module vulnerability.sh
    run_phase "Vulnerability Research" "$MODULES_DIR/vulnerability.sh" "$TARGET"
}

phase_correlation() {
    assert_module correlation.sh
    run_phase "Finding Correlation" "$MODULES_DIR/correlation.sh" "$TARGET"
}

phase_exploit() {
    assert_module exploitation.sh
    run_phase "Lab Exploitation (Metasploit)" "$MODULES_DIR/exploitation.sh" "$TARGET"
}

phase_evidence() {
    assert_module evidence.sh
    run_phase "Evidence / Session" "$MODULES_DIR/evidence.sh" "$TARGET"
}

phase_report() {
    assert_module report.sh
    run_phase "Report Generation" "$MODULES_DIR/report.sh" "$TARGET"
}

# ---------------------------------------------------------------
# Assessment-mode phase runner
# ---------------------------------------------------------------

run_assessment_phase() {
    local id="$1" phase="$2" mod rc=0
    mod="$(sat_assessment_module_name "$phase")"
    assert_module "$mod"
    sat_assessment_set_outputs
    sat_assessment_manifest_set "$id" current_phase "$phase" || return 1
    run_phase "$phase" "$MODULES_DIR/$mod" "$ASSESSMENT_TARGET" || rc=$?
    if (( rc == 0 )); then
        sat_assessment_add_completed "$id" "$phase"
    else
        sat_assessment_add_failed "$id" "$phase"
    fi
    return "$rc"
}

run_assessment() {
    local target="$1" mode="$2" id
    local failrc=0 rc=0 phase plan exprc=0 ran_report=0
    if ! sat_assessment_create "$target"; then
        echo "[-] Assessment creation failed." >&2
        return 1
    fi
    id="$SAT_ASSESSMENT_ID"
    echo
    echo "[+] Assessment created:"
    echo "    id:     $id"
    echo "    target: $target"
    echo "    dir:    $ASSESSMENTS_ROOT/$id"
    echo

    if [[ "$mode" == "quick" ]]; then
        plan="discovery enumeration"
    else
        plan="discovery enumeration vulnerabilities correlation exploitation evidence report"
    fi

    echo "[+] Phase plan: $plan"
    echo

    for phase in $plan; do
        [[ "$phase" == "report" ]] && ran_report=1
        run_assessment_phase "$id" "$phase" || rc=$?
        if (( rc != 0 )); then
            if [[ "$phase" == "exploitation" ]]; then
                # Exploitation is approval-gated. Cancelled/denied/no-session
                # still lets evidence + report record the honest outcome.
                exprc=$rc
                failrc=$rc
            elif (( exprc == 0 )); then
                failrc=$rc
                break
            fi
        fi
    done

    # A failed pre-exploitation chain still gets an honest report,
    # but only full (not quick) scans produce a report at all.
    if (( ran_report != 1 )) && [[ "$mode" != "quick" ]]; then
        run_assessment_phase "$id" report || true
    fi

    if (( failrc == 0 )); then
        sat_assessment_manifest_set "$id" status completed current_phase ""
        echo
        echo "[+] Assessment completed: $id"
        echo "    Report: $ASSESSMENTS_ROOT/$id/report/"
    else
        sat_assessment_manifest_set "$id" status failed
        echo
        echo "[!] Assessment finished with errors (rc=$failrc): $id"
        echo "    Phase 5 (exploitation) only ever ran with explicit in-run approval."
        echo "    Resume later with: ./$0 resume $id"
    fi
    return "$failrc"
}

# ---------------------------------------------------------------
# dry-run helpers
# ---------------------------------------------------------------

dry_run_print() {
    local id="$1" target="$2" plan="$3" phase mod
    echo
    echo "[*] Would create assessment: $id"
    echo "    base dir: $ASSESSMENTS_ROOT/$id/"
    echo
    echo "[*] Would execute the following phases/commands:"
    for phase in $plan; do
        mod="$(sat_assessment_module_name "$phase")"
        echo "    $phase:"
        echo "      modules/$mod $target"
        echo "      artifacts: $ASSESSMENTS_ROOT/$id/$phase/"
    done
    echo
    echo "[*] Dependencies by phase:"
    echo "    discovery/enumeration : nmap"
    echo "    vulnerabilities        : python3, searchsploit (optional but reduces findings)"
    echo "    correlation/report     : python3"
    echo "    exploitation (manual)  : nmap, msfconsole  (never auto-run)"
    echo "    evidence (after exploit): python3"
    echo
    echo "    Phase 5 (exploitation) will NOT be run automatically."
    echo "    No assessment is created and no command is executed during a dry run."
}

# ---------------------------------------------------------------
# Unified CLI commands
# ---------------------------------------------------------------

cmd_help() {
    echo "Usage: $0 <command> [options]"
    echo
    echo "Assessment commands:"
    echo "  $0 scan <target> [--quick|--full|--dry-run]"
    echo "      Create a new isolated assessment and run the non-exploit pipeline"
    echo "      (discovery, enumeration, vulnerabilities, correlation, report;"
    echo "      --quick = discovery + enumeration only)."
    echo "  $0 status [<assessment-id>]"
    echo "      List all assessments, or show the detailed state of one."
    echo "  $0 resume <assessment-id> [--dry-run]"
    echo "      Continue an assessment: skip completed phases, retry failed,"
    echo "      never auto-exploit. --dry-run only prints the plan."
    echo "  $0 report <assessment-id>"
    echo "      (Re)generate the report for an assessment."
    echo "  $0 scope <list|create|show|status|expand> ..."
    echo "      Manage scope targets under one logical assessment."
    echo "  $0 scan <scope_id> [--new|--failed|--all|--targets a,b,c] [--workers N] [--dry-run]"
    echo "      Scan scope targets with a bounded parallel worker pool."
    echo "      (selected targets still get per-target isolated artifacts)"
    echo "  $0 history [<assessment-id>]"
    echo "      Audit log of every assessment (and its scopes)."
    echo "  $0 compare <assessment-id-A> <assessment-id-B>"
    echo "      Side-by-side phase/artifact comparison of two assessments."
    echo "  $0 preflight [<target>]"
    echo "      Check required/optional tools, config, output writability and"
    echo "      lightweight target reachability."
    echo "  $0 menu"
    echo "      Interactive main menu (no auto-exploit, Ctrl+C to exit)."
    echo
    echo "Scope commands:"
    echo "  $0 scan <scope_id> [--new|--failed|--all|--targets a,b] [--workers N] [--dry-run]"
    echo "      Scan a scope's targets in bounded parallel workers, one isolated"
    echo "      output dir per target. Never auto-exploits."
    echo "  $0 scope list [<assessment-id>]"
    echo "  $0 scope create <assessment-id> <targets...> [--name <n>] [--parent <scope_id>]"
    echo "      Normalizes/dedupes targets, expands CIDR ranges with a size cap."
    echo "  $0 scope show <scope_id>"
    echo "  $0 scope status <scope_id>"
    echo "  $0 scope expand <scope_id> <targets...>"
    echo "      Adds targets to an existing scope (never deletes previous results)."
    echo "  $0 resume <assessment-id>"
    echo "      Resumes scope-based assessments per scope instead of phases."
    echo
    echo "History commands:"
    echo "  $0 history [<assessment-id>]   summary audit log of all assessments"
    echo "  $0 compare <id-A> <id-B>       side-by-side phase/artifact comparison"
    echo
    echo "Legacy phase commands:"
    echo "  $0 <target> discovery|enumeration|vulnerabilities|correlation|"
    echo "  $0 <target> exploit|evidence|report"
    echo "      Each runs ONLY its single phase - nothing is chained."
    echo "  $0 <target> full   (full pipeline: discovery, enumeration,"
    echo "       vulnerabilities, correlation, exploitation [approval required],"
    echo "       evidence, report)"
    echo "  $0 <target> all    (discovery + enumeration only)"
}

cmd_scan() {
    local target="" mode="full" dry=0
    local workers=""
    local sel="pending"
    local -a sel_targets=()
    while (( $# > 0 )); do
        case "$1" in
            --quick) mode="quick"; sel="pending" ;;
            --full) mode="full" ;;
            --dry-run) dry=1 ;;
            --new) sel="pending" ;;
            --failed) sel="failed" ;;
            --all) sel="all" ;;
            --targets) sel="selected"; IFS=',' read -r -a sel_targets <<< "$2"; shift ;;
            --workers) workers="$2"; shift ;;
            -*) echo "[-] Unknown scan option: $1" >&2; exit 1 ;;
            *) target="$1" ;;
        esac
        shift
    done

    # Scope-based scan: <scope_*> targets, parallel workers, bounded timeouts.
    if [[ -n "${target:-}" && "$target" == scope_* ]]; then
        cmd_scope_scan "$target" "$mode" "$dry" "$sel" "$workers" "${sel_targets[@]:-}"
        exit $?
    fi
    if [[ "$sel" != "pending" || ${#sel_targets[@]} -gt 0 || -n "$workers" ]]; then
        echo "[-] Selection flags (--new/--failed/--all/--targets/--workers) only apply to a scope scan." >&2
        echo "    For a single target use: $0 scan <ip> [--quick|--full|--dry-run]" >&2
        exit 1
    fi

    if [[ -z "$target" ]]; then
        read -r -p "[?] Enter target IP: " target
    fi
    if [[ -z "$target" ]]; then
        echo "[-] Target cannot be empty." >&2
        exit 1
    fi
    sat_validate_target "$target" || {
        echo "[-] Invalid target: $target" >&2
        exit 1
    }

    echo "[+] Target: $target"
    echo
    load_config
    sat_apply_defaults

    local plan
    if [[ "$mode" == "quick" ]]; then
        plan="discovery enumeration"
    else
        plan="discovery enumeration vulnerabilities correlation report"
    fi

    if (( dry == 1 )); then
        echo "[*] Dry run requested: scan $target ($mode)"
        local pid
        pid="$(sat_assessment_id_new)"
        dry_run_print "$pid" "$target" "$plan"
        exit 0
    fi

    check_dependencies "assessment"
    run_assessment "$target" "$mode"
    exit $?
}

cmd_status() {
    local id="${1:-}"

    if [[ -n "$id" ]]; then
        if ! sat_assessment_load "$id"; then
            exit 1
        fi
        echo "[+] Assessment: $id"
        echo
        python3 - "$id" "$ASSESSMENT_DIR/manifest.json" <<'PY'
import json
import os
import sys

aid, path = sys.argv[1:3]
root = os.path.dirname(path)
m = json.load(open(path))

by_phase = {}
for k in ("completed_phases", "failed_phases"):
    for p in m.get(k, []):
        by_phase[p] = k.replace("_phases", "")


def has_artifacts(phase):
    d = os.path.join(root, phase)
    if phase in ("discovery", "enumeration"):
        return bool(glob_any(d, "*"))
    if phase == "vulnerabilities":
        return bool(glob_any(d, "*", "services.tsv"))
    if phase == "correlation":
        return bool(glob_any(root, "vulnerabilities", "*", "correlated_findings.tsv"))
    if phase == "exploitation":
        return bool(glob_any(d, "*", "result.txt"))
    if phase == "evidence":
        return bool(glob_any(d, "*", "session.txt"))
    if phase == "report":
        return bool(glob_any(d, "*_*.md") or glob_any(d, "*_*.html"))
    return False


def glob_any(*parts):
    import glob as _g
    return _g.glob(os.path.join(*parts))

print("  target       : %s" % m.get("target"))
print("  started_at   : %s" % m.get("started_at"))
print("  updated_at   : %s" % m.get("updated_at"))
print("  status       : %s" % m.get("status"))
print("  current_phase: %s" % m.get("current_phase") or "-")
print()
print("  phase                   state")
print("  ----------------------- -------")
for phase in ("discovery", "enumeration", "vulnerabilities", "correlation",
              "exploitation", "evidence", "report"):
    state = by_phase.get(phase)
    if state == "completed" and not has_artifacts(phase):
        state = "completed (artifacts missing!)"
    if phase == "exploitation" and state is None:
        state = "manual-only (not run)"
    if phase == "evidence" and state is None:
        state = "skipped (no exploitation result)"
    print("  %-23s %s" % (phase, state or "pending"))
PY
        if compgen -G "$ASSESSMENT_DIR/scopes/scope_"* >/dev/null 2>&1; then
            echo
            echo "  Scopes in this assessment:"
            echo "    scope                         state       targets"
            echo "    ----------------------------  ----------  -------"
            local sd sid
            for sd in "$ASSESSMENT_DIR"/scopes/scope_*; do
                [[ -d "$sd" ]] || continue
                sid="$(basename "$sd")"
                python3 - "$sd/scope.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print("    %-28s  %-10s  %7d" % (
    m.get("scope_id", "-"), m.get("status", "-"), m.get("target_count", 0)))
PY
            done
            echo
            echo "  (per-target detail: $0 scope status <scope_id>)"
        fi
        exit 0
    fi

    local mf
    local found=0
    echo "[+] Assessments:"
    for mf in "$ASSESSMENTS_ROOT"/assessment_*/manifest.json; do
        [[ -f "$mf" ]] || continue
        found=1
        python3 - "$mf" <<'PY'
import json
import os
import sys

path = sys.argv[1]
m = json.load(open(path))
aid = m.get("assessment_id", os.path.basename(os.path.dirname(path)))
print("  %-46s %-15s %-12s %s" % (
    aid, m.get("target", "-"), m.get("status", "-"),
    ",".join(m.get("completed_phases", []) or [])))
PY
    done
    if (( found == 0 )); then
        echo "  (none)"
        echo
        echo "No assessments found yet. Start one with: $0 scan <target>"
        exit 0
    fi
}

cmd_resume() {
    local id="" dry=0
    while (( $# > 0 )); do
        case "$1" in
            --dry-run) dry=1 ;;
            -*) echo "[-] Unknown resume option: $1" >&2; exit 1 ;;
            *) id="$1" ;;
        esac
        shift
    done

    if [[ -z "$id" ]]; then
        echo "Usage: $0 resume <assessment-id> [--dry-run]" >&2
        exit 1
    fi

    load_config
    sat_apply_defaults

    if ! sat_assessment_load "$id"; then
        exit 1
    fi

    # Scope-based assessments resume per scope (parallel targets), never as
    # assessment-level phases.
    if compgen -G "$ASSESSMENT_DIR/scopes/scope_"* >/dev/null 2>&1; then
        scope_resume "$id" "$dry"
        exit $?
    fi

    sat_assessment_build_plan "$id"
    local plan="$SAT_PLAN"

    if [[ -z "$plan" ]]; then
        echo
        echo "[+] Nothing to resume for '$id' - all runnable phases are already complete."
        echo "    Remaining work (exploitation/evidence) requires an explicit command:"
        echo "      $0 $ASSESSMENT_TARGET exploit"
        exit 0
    fi

    echo
    echo "[+] Resume plan for '$id': $plan"
    echo "    Skipping completed phases; failed phases are retried."
    echo "    Phase 5 (exploitation) is NEVER run automatically."

    if (( dry == 1 )); then
        dry_run_print "$id" "$ASSESSMENT_TARGET" "$plan"
        echo "[-] Dry run: no phase was executed and nothing was modified."
        exit 0
    fi

    local failrc=0 phase ran_report=0
    for phase in $plan; do
        [[ "$phase" == "report" ]] && ran_report=1
        run_assessment_phase "$id" "$phase" || failrc=$?
        if (( failrc != 0 )); then
            break
        fi
    done

    if (( failrc != 0 )) && (( ran_report != 1 )); then
        run_assessment_phase "$id" report || true
    fi

    if (( failrc == 0 )); then
        sat_assessment_manifest_set "$id" status completed current_phase ""
        echo
        echo "[+] Assessment resumed to completion: $id"
        echo "    Report: $ASSESSMENTS_ROOT/$id/report/"
    else
        sat_assessment_manifest_set "$id" status failed
        echo
        echo "[!] Resume stopped with errors (rc=$failrc): $id"
    fi
    exit "$failrc"
}

cmd_report() {
    local id="${1:-}" rc=0
    if [[ -z "$id" ]]; then
        echo "Usage: $0 report <assessment-id>" >&2
        exit 1
    fi

    load_config
    sat_apply_defaults

    if ! sat_assessment_load "$id"; then
        exit 1
    fi

    echo "[+] (Re)generating report for assessment '$id' (target $ASSESSMENT_TARGET)."
    assert_module report.sh
    sat_assessment_set_outputs
    run_phase "Report Generation" "$MODULES_DIR/report.sh" "$ASSESSMENT_TARGET" || rc=$?
    if (( rc == 0 )); then
        sat_assessment_add_completed "$id" report
        sat_assessment_manifest_set "$id" status completed current_phase ""
        echo
        echo "[+] Report written to: $ASSESSMENTS_ROOT/$id/report/"
    else
        sat_assessment_add_failed "$id" report
        echo
        echo "[!] Report generation failed (rc=$rc)." >&2
    fi
    exit "$rc"
}

# ---------------------------------------------------------------
# Scope commands (Phase 10-11)
# ---------------------------------------------------------------

cmd_scope() {
    local sub="${1:-}"
    shift 2>/dev/null || true
    load_config
    sat_apply_defaults
    case "$sub" in
        list)           cmd_scope_list "$@" ;;
        create)         cmd_scope_create_cmd "$@" ;;
        show)           cmd_scope_show "$@" ;;
        status)         cmd_scope_status "$@" ;;
        expand)         cmd_scope_expand_cmd "$@" ;;
        *)
            echo "Usage: $0 scope <command> [args]" >&2
            echo "  $0 scope list [<assessment-id>]" >&2
            echo "  $0 scope create <assessment-id> <targets...> [--name <n>] [--parent <scope_id>]" >&2
            echo "  $0 scope show <scope_id>" >&2
            echo "  $0 scope status <scope_id>" >&2
            echo "  $0 scope expand <scope_id> <targets...>" >&2
            exit 1
            ;;
    esac
}

cmd_scope_list() {
    local aid="${1:-}"
    local roots=() d
    if [[ -n "$aid" ]]; then
        [[ -d "$ASSESSMENTS_ROOT/$aid/scopes" ]] && roots=("$ASSESSMENTS_ROOT/$aid/scopes")
    else
        for d in "$ASSESSMENTS_ROOT"/assessment_*; do
            [[ -d "$d/scopes" ]] && roots+=("$d/scopes")
        done
    fi

    echo "[+] Scopes:"
    echo "  scope_id              type      targets  state       assessment"
    echo "  --------------------  --------  -------  ----------  -------------"
    local root sd sid found=0
    for root in ${roots[@]:-}; do
        for sd in "$root"/scope_*; do
            [[ -d "$sd" ]] || continue
            found=1
            sid="$(basename "$sd")"
            python3 - "$sd/scope.json" "$sid" "$(basename "$(dirname "$root")")" <<'PY'
import json, sys
p, sid, aid = sys.argv[1:4]
m = json.load(open(p))
print("  %-20s  %-8s  %7d  %-10s  %s" % (
    sid, m.get("type", "-"), m.get("target_count", 0), m.get("status", "-"), aid))
PY
        done
    done
    if (( found == 0 )); then
        echo "  (no scopes found)"
        exit 0
    fi
}

cmd_scope_create_cmd() {
    local aid="${1:-}"
    shift 2>/dev/null || true
    if [[ -z "$aid" ]]; then
        echo "Usage: $0 scope create <assessment-id> <targets...> [--name <n>]" >&2
        exit 1
    fi
    sat_assessment_ensure "$aid" || exit $?
    if ! sat_scope_create "$aid" "$@"; then
        echo "[-] Scope creation failed." >&2
        exit 1
    fi
}

cmd_scope_show() {
    local sid="${1:-}"
    if [[ -z "$sid" ]]; then
        echo "Usage: $0 scope show <scope_id>" >&2
        exit 1
    fi
    sat_scope_resolve "$sid" || { echo "[-] Unknown scope: $sid" >&2; exit 1; }
    python3 - "$SAT_SCOPE_DIR/scope.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
for k in ("scope_id", "assessment_id", "name", "type", "created_at", "status",
          "parent_scope_id", "target_count", "completed_target_count", "last_run"):
    v = m.get(k)
    print("  %-22s %s" % (k, v if v is not None else "-"))
print("  %-22s %d" % ("targets", len(m.get("targets", []))))
PY
    echo
    sat_scope_summary "$sid"
}

cmd_scope_status() {
    local sid="${1:-}"
    if [[ -z "$sid" ]]; then
        echo "Usage: $0 scope status <scope_id>" >&2
        exit 1
    fi
    sat_scope_resolve "$sid" || { echo "[-] Unknown scope: $sid" >&2; exit 1; }
    sat_scope_summary "$sid"
}

cmd_scope_expand_cmd() {
    local sid="${1:-}"
    shift 2>/dev/null || true
    if [[ -z "$sid" ]]; then
        echo "Usage: $0 scope expand <scope_id> <targets...>" >&2
        exit 1
    fi
    sat_scope_expand "$sid" "$@"
}

# ---------------------------------------------------------------
# Scope scan (Phase 11) - bounded parallel workers per target
# ---------------------------------------------------------------

# scan_scope_pool <aid> <sid> <workers> <timeout> <targets...>
# Launches one isolated worker per target; at most <workers> in flight.
# Returns 0, 2 (some targets failed), or 124 (any worker timed out).
scan_scope_pool() {
    local aid="$1" sid="$2" workers="$3" tmo="$4"
    shift 4
    local -a pids=()
    local target rc any_timeout=0 total_fail=0 i

    for target in "$@"; do
        # bounded pool: wait until a slot frees before spawning
        while (( ${#pids[@]} >= workers )); do
            local free=0
            for i in "${!pids[@]}"; do
                if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                    wait "${pids[$i]}" 2>/dev/null || rc=$?
                    (( rc == 124 )) && any_timeout=1
                    (( rc != 0 && rc != 124 )) && total_fail=$((total_fail + 1))
                    unset 'pids[i]'
                    free=1
                    break
                fi
            done
            if (( free == 1 )); then
                local np=()
                for i in "${pids[@]:-}"; do np+=("$i"); done
                pids=("${np[@]}")
            else
                sleep 0.2
            fi
        done
        echo "[*] scope worker: $target (workers in flight: ${#pids[@]})"
        timeout --kill-after=10s "$tmo" bash "$PROJECT_ROOT/lib/scope_worker.sh" \
            "$aid" "$sid" "$target" &
        pids+=("$!")
    done

    for i in "${pids[@]:-}"; do
        wait "$i" 2>/dev/null || rc=$?
        (( rc == 124 )) && any_timeout=1
        (( rc != 0 && rc != 124 )) && total_fail=$((total_fail + 1))
    done

    SAT_SCOPE_TIMED_OUT="$any_timeout"
    SAT_SCOPE_FAILED_COUNT="$total_fail"
    if (( any_timeout == 1 )); then
        echo "[!] At least one worker hit the ${tmo}s per-target timeout and was marked failed."
    fi
    if (( total_fail > 0 )); then
        echo "[!] $total_fail target(s) failed. Retry later with:"
        echo "      $0 scan $sid --failed"
    fi
    if (( any_timeout == 1 )); then return 124; fi
    if (( total_fail > 0 )); then return 2; fi
    return 0
}

# cmd_scope_scan <sid> <mode> <dry> <sel> <workers> [selected targets...]
cmd_scope_scan() {
    local sid="$1" mode="$2" dry="$3" sel="$4" workers="$5"
    shift 5
    local -a sel_targets=("$@")

    check_dependencies "assessment"
    [[ "$mode" == "quick" ]] && mode="full"

    if ! sat_scope_resolve "$sid"; then
        echo "[-] Unknown scope: $sid" >&2
        exit 1
    fi
    local aid="$SAT_SCOPE_ASSESSMENT"

    local wmax="${workers:-$ENUMERATION_WORKERS}"
    if [[ ! "$wmax" =~ ^[0-9]+$ || "$wmax" -lt 1 ]]; then
        echo "[-] --workers must be an integer >= 1 (got '$wmax')." >&2
        exit 1
    fi
    local tmo="${SCOPE_TARGET_TIMEOUT:-900}"

    local selected=""
    if [[ "$sel" == "selected" ]]; then
        selected="$(sat_scope_selected "$sid" selected -- "${sel_targets[@]:-}")"
    else
        selected="$(sat_scope_selected "$sid" "$sel")" || exit $?
    fi
    if [[ -z "$selected" ]]; then
        echo "[+] Scope $sid: nothing to do (selection '$sel' is empty)."
        sat_scope_summary "$sid"
        exit 0
    fi

    echo
    echo "[*] Scope scan plan:"
    echo "    scope      : $sid"
    echo "    name       : $(sat_scope_meta_get "$sid" name)"
    echo "    assessment : $aid"
    echo "    selection  : $sel"
    echo "    targets    : $(wc -w <<<"$selected") of $(sat_scope_meta_get "$sid" target_count)"
    echo "    workers    : $wmax (parallel, isolated per-target state)"
    echo "    timeout    : ${tmo}s per target (killed + marked failed on expiry)"
    echo
    local t shown=0
    for t in $selected; do
        (( shown < 10 )) && echo "      - $t"
        shown=$((shown + 1))
    done
    (( shown > 10 )) && echo "      ... and $(( shown - 10 )) more"

    if (( dry == 1 )); then
        echo
        echo "[-] Dry run: no target was scanned and nothing was modified."
        exit 0
    fi

    sat_scope_meta_set "$sid" status running last_run "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    echo
    echo "######## SCOPE SCAN: $sid ($sel, workers=$wmax) ########"
    echo

    scan_scope_pool "$aid" "$sid" "$wmax" "$tmo" $selected
    local agg=$?
    echo
    sat_scope_summary "$sid"
    exit "$agg"
}

# ---------------------------------------------------------------
# Scope-based resume (assessment with scopes resumably by scope)
# ---------------------------------------------------------------

scope_resume() {
    local aid="$1" dry="$2"
    local sid_dir sid target uniq="" sel
    local any_timeout=0 total_fail=0 rc=0

    echo "[+] Scope-based resume for '$aid':"
    for sid_dir in "$ASSESSMENTS_ROOT/$aid"/scopes/scope_*; do
        [[ -d "$sid_dir" ]] || continue
        sid="$(basename "$sid_dir")"
        sel="$(sat_scope_selected "$sid" pending) $(sat_scope_selected "$sid" failed)" || true
        uniq=""
        for target in $sel; do
            [[ " $uniq " == *" $target "* ]] && continue
            uniq+=" $target"
        done
        uniq="${uniq# }"

        if [[ -z "$uniq" ]]; then
            echo "[+] Scope $sid: nothing to resume."
            continue
        fi
        echo "[*] Scope $sid: resuming $(wc -w <<<"$uniq") target(s)."
        echo
        if (( dry == 1 )); then
            for target in $uniq; do echo "    - $target"; done
            continue
        fi
        sat_scope_meta_set "$sid" status running last_run "$(date '+%Y-%m-%dT%H:%M:%S%z')"
        scan_scope_pool "$aid" "$sid" "$ENUMERATION_WORKERS" "${SCOPE_TARGET_TIMEOUT:-900}" $uniq
        rc=$?
        if (( ${SAT_SCOPE_TIMED_OUT:-0} == 1 )); then any_timeout=1; fi
        total_fail=$((total_fail + ${SAT_SCOPE_FAILED_COUNT:-0}))
        sat_scope_summary "$sid"
        echo
    done

    if (( any_timeout == 1 )); then return 124; fi
    if (( total_fail > 0 )); then return 2; fi
    return 0
}

# ---------------------------------------------------------------
# History / audit log and assessment comparison
# ---------------------------------------------------------------

cmd_history() {
    local aid="${1:-}"
    load_config
    sat_apply_defaults

    # Detailed, read-only view of one historical assessment.
    # Errors (missing/corrupt/unknown, incomplete history) exit 1 with a
    # clear message - history NEVER rewrites or fabricates historical state.
    if [[ -n "$aid" ]]; then
        if [[ "$aid" != assessment_* ]]; then
            echo "[-] Invalid assessment id: '$aid' (must start with 'assessment_')." >&2
            exit 1
        fi
        python3 "$PROJECT_ROOT/lib/history.py" "$ASSESSMENTS_ROOT" "$aid" || exit $?
        exit 0
    fi

    echo "[+] Assessment history (audit log):"
    python3 - "$ASSESSMENTS_ROOT" "${aid:-}" <<'PY'
import glob, json, os, sys
root, only = sys.argv[1:3]
rows = []
for mf in glob.glob(os.path.join(root, "assessment_*", "manifest.json")):
    m = json.load(open(mf))
    aid = m.get("assessment_id", os.path.basename(os.path.dirname(mf)))
    if only and aid != only:
        continue
    scopes = 0
    sd = os.path.join(os.path.dirname(mf), "scopes")
    if os.path.isdir(sd):
        scopes = len([d for d in glob.glob(os.path.join(sd, "scope_*"))
                      if os.path.isdir(d)])
    rows.append((m.get("started_at", ""), aid,
                 m.get("target") or "(scope-based, %d scope(s))" % scopes,
                 m.get("status", "-"), len(m.get("completed_phases", []) or []), scopes))
if not rows:
    print("  (no assessments recorded)")
    sys.exit(0)
print("  %-22s %-46s %-15s %-10s %-7s %s" % ("started_at", "assessment_id", "target", "status", "phases", "scopes"))
for r in sorted(rows):
    print("  %-22s %-46s %-15s %-10s %-7d %d" % r)
PY
}

cmd_compare() {
    local a="${1:-}" b="${2:-}"
    if [[ -z "$a" || -z "$b" ]]; then
        echo "Usage: $0 compare <assessment-id-A> <assessment-id-B>" >&2
        exit 1
    fi
    load_config
    sat_apply_defaults
    if [[ ! -f "$ASSESSMENTS_ROOT/$a/manifest.json" ]]; then
        echo "[-] Unknown assessment: $a" >&2
        exit 1
    fi
    if [[ ! -f "$ASSESSMENTS_ROOT/$b/manifest.json" ]]; then
        echo "[-] Unknown assessment: $b" >&2
        exit 1
    fi

    # Comparison is a read-only operation: the artifact goes to a NEW
    # per-run directory under OUTPUT_COMPARE, never into the assessments.
    local ts outdir
    ts="$(sat_timestamp)"
    outdir="$OUTPUT_COMPARE/${a}__vs__${b}_${ts}"
    mkdir -p "$outdir" || { echo "[-] Could not create comparison output: $outdir" >&2; exit 1; }

    python3 "$PROJECT_ROOT/lib/comparison.py" "$ASSESSMENTS_ROOT" "$a" "$b" "$outdir" || exit $?

    echo
    echo "[+] Comparison written to:"
    echo "    $outdir/comparison.json"
    echo "    $outdir/summary.txt"
    echo "    $outdir/status.txt"
}

cmd_preflight() {
    local target="${1:-}"
    if [[ -z "$target" ]]; then
        read -r -p "[?] Enter target IP: " target
    fi
    if [[ -z "$target" ]]; then
        echo "[-] Target cannot be empty." >&2
        exit 1
    fi
    sat_validate_target "$target" || {
        echo "[-] Invalid target: $target" >&2
        exit 1
    }

    load_config
    sat_apply_defaults

    echo "========== PREFLIGHT CHECKS =========="
    echo "  target: $target"
    echo

    local fail=0 t

    echo "[*] Required tools:"
    for t in bash python3 nmap; do
        if command -v "$t" >/dev/null 2>&1; then
            echo "  [+] $t: OK"
        else
            echo "  [-] $t: NOT FOUND (required)" >&2
            fail=1
        fi
    done

    echo
    echo "[*] Optional tools (per-phase availability):"
    if command -v searchsploit >/dev/null 2>&1; then
        echo "  [+] searchsploit: OK - Phase 3 (vulnerability research) available"
    else
        echo "  [!] searchsploit: NOT FOUND - Phase 3 will run with zero candidates (optional)"
    fi
    if command -v msfconsole >/dev/null 2>&1; then
        echo "  [+] msfconsole: OK - Phase 5 (exploitation) available"
    else
        echo "  [!] msfconsole: NOT FOUND - Phase 5 unavailable (optional, never auto-run)"
    fi

    echo
    echo "[*] Configuration:"
    if [[ -f "$CONFIG_FILE" ]]; then
        echo "  [+] config file: $CONFIG_FILE"
    else
        echo "  [-] config file missing: $CONFIG_FILE" >&2
        fail=1
    fi

    echo
    echo "[*] Scope / parallel settings:"
    if [[ "$ENUMERATION_WORKERS" =~ ^[0-9]+$ ]] && (( ENUMERATION_WORKERS >= 1 )); then
        echo "  [+] parallel workers  : $ENUMERATION_WORKERS (1 = sequential)"
    else
        echo "  [-] parallel workers  : '$ENUMERATION_WORKERS' is not an integer >= 1" >&2
        fail=1
    fi
    if [[ "$SCOPE_TARGET_TIMEOUT" =~ ^[0-9]+$ ]] && (( SCOPE_TARGET_TIMEOUT > 0 )); then
        echo "  [+] per-target timeout: ${SCOPE_TARGET_TIMEOUT}s"
    else
        echo "  [-] per-target timeout: '$SCOPE_TARGET_TIMEOUT' is not a positive integer" >&2
        fail=1
    fi
    if [[ "$SCOPE_MAX_EXPANDED_TARGETS" =~ ^[0-9]+$ ]] && (( SCOPE_MAX_EXPANDED_TARGETS > 0 )); then
        echo "  [+] CIDR expansion cap : $SCOPE_MAX_EXPANDED_TARGETS hosts per range"
    else
        echo "  [-] CIDR expansion cap : '$SCOPE_MAX_EXPANDED_TARGETS' is not a positive integer" >&2
        fail=1
    fi

    echo
    echo "[*] Output writability:"
    local wbase=""
    if wbase="$(writable_ancestor "$ASSESSMENTS_ROOT")"; then
        echo "  [+] writable base for assessments: $wbase"
    else
        echo "  [-] no writable ancestor found for assessment output" >&2
        fail=1
    fi

    echo
    echo "[*] Target reachability (informational, lightweight):"
    local said=""
    if command -v ping >/dev/null 2>&1; then
        if ping -c1 -W2 "$target" >/dev/null 2>&1; then
            echo "  [+] target responded to ICMP"
            said=1
        else
            echo "  [!] target did not respond to ICMP (will be confirmed by Phase 1/2)"
        fi
    else
        echo "  [!] ping not available - reachability deferred to Phase 1/2"
    fi
    if command -v nmap >/dev/null 2>&1; then
        echo "  [*] Phase 1/2 run the authoritative reachability check at scan time."
    fi

    echo
    echo "[*] Phase availability summary:"
    if command -v nmap >/dev/null 2>&1; then
        echo "  [+] discovery / enumeration      : available"
    else
        echo "  [-] discovery / enumeration      : unavailable (nmap required)" >&2
    fi
    if command -v python3 >/dev/null 2>&1; then
        echo "  [+] vulnerabilities / correlation: available"
    else
        echo "  [-] vulnerabilities / correlation: unavailable (python3 required)" >&2
    fi
    if command -v msfconsole >/dev/null 2>&1; then
        echo "  [+] exploitation (manual, approved): available"
    else
        echo "  [-] exploitation (manual, approved): msfconsole not found" >&2
    fi
    if command -v python3 >/dev/null 2>&1; then
        echo "  [+] evidence / report            : available"
    else
        echo "  [-] evidence / report            : unavailable (python3 required)" >&2
    fi

    echo
    if (( fail == 1 )); then
        echo "[-] Preflight FAILED: one or more required checks failed." >&2
        exit 1
    fi
    echo "[+] Preflight OK - required checks passed (optional gaps are warnings only)."
}

writable_ancestor() {
    # Prints the nearest existing writable ancestor of the given path.
    local p="$1"
    while [[ -n "$p" && "$p" != "/" ]]; do
        if [[ -d "$p" && -w "$p" ]]; then
            printf '%s' "$p"
            return 0
        fi
        p="$(dirname "$p")"
    done
    return 1
}

cmd_menu() {
    trap 'echo; echo "[*] Interrupted."; exit 130' INT
    local target="" choice phase
    while true; do
        echo
        echo "========== SECURITY ASSESSMENT TOOL - MAIN MENU =========="
        echo "  0) Exit"
        echo "  1) Preflight"
        echo "  2) Full scan (new assessment, no exploit)"
        echo "  3) Quick scan (discovery + enumeration)"
        echo "  4) Discovery"
        echo "  5) Enumeration"
        echo "  6) Vulnerabilities"
        echo "  7) Correlation"
        echo "  8) Exploitation (requires explicit approval)"
        echo "  9) Evidence"
        echo " 10) Report"
        echo " 11) Status"
        echo " 12) Scope manager (list/create/status/scan)"
        echo " 13) History (audit log)"
        echo " 14) Compare two assessments"
        echo "=========================================================="
        read -r -p "[?] Select option (0-14): " choice || { echo; exit 130; }
        case "$choice" in
            0) echo "[+] Goodbye."; exit 0 ;;
            1) menu_enter_target; "$0" preflight "$target" ;;
            2)
                menu_enter_target
                "$0" scan "$target" --full
                ;;
            3)
                menu_enter_target
                "$0" scan "$target" --quick
                ;;
            4) menu_enter_target; "$0" "$target" discovery ;;
            5) menu_enter_target; "$0" "$target" enumeration ;;
            6) menu_enter_target; "$0" "$target" vulnerabilities ;;
            7) menu_enter_target; "$0" "$target" correlation ;;
            8) menu_enter_target; "$0" "$target" exploit ;;
            9) menu_enter_target; "$0" "$target" evidence ;;
            10) menu_enter_target; "$0" "$target" report ;;
            11) "$0" status ;;
            12) cmd_menu_scope ;;
            13) "$0" history ;;
            14)
                read -r -p "[?] Assessment id A: " ca
                read -r -p "[?] Assessment id B: " cb
                "$0" compare "$ca" "$cb"
                ;;
            *) echo "[!] Invalid option: $choice" ;;
        esac
    done
}

cmd_menu_scope() {
    while true; do
        echo
        echo "---- SCOPE MANAGER ----"
        echo "  0) Back to main menu"
        echo "  1) List scopes"
        echo "  2) Create scope (assessment + targets)"
        echo "  3) Show scope status"
        echo "  4) Scan scope (new targets, parallel workers)"
        echo "-----------------------"
        read -r -p "[?] Select (0-4): " c2 || { echo; return 0; }
        case "$c2" in
            0) return 0 ;;
            1) "$0" scope list ;;
            2)
                read -r -p "[?] Assessment id: " ca
                read -r -p "[?] Targets (comma separated): " ct
                if [[ -n "$ca" && -n "$ct" ]]; then
                    "$0" scope create "$ca" ${ct//,/ }
                else
                    echo "[!] Assessment id and targets are required." >&2
                fi
                ;;
            3)
                read -r -p "[?] Scope id: " cs
                [[ -n "$cs" ]] && "$0" scope status "$cs"
                ;;
            4)
                read -r -p "[?] Scope id: " cs
                read -r -p "[?] Workers (default from config): " cw
                if [[ -n "$cs" ]]; then
                    if [[ -n "$cw" ]]; then
                        "$0" scan "$cs" --new --workers "$cw"
                    else
                        "$0" scan "$cs" --new
                    fi
                fi
                ;;
            *) echo "[!] Invalid option: $c2" ;;
        esac
    done
}

menu_enter_target() {
    if [[ -n "${target:-}" ]]; then
        return 0
    fi
    local t=""
    read -r -p "[?] Enter target IP: " t || { echo; exit 130; }
    t="${t:-}"
    if [[ -z "$t" ]]; then
        echo "[-] Target cannot be empty." >&2
        exit 1
    fi
    sat_validate_target "$t" || {
        echo "[-] Invalid target: $t" >&2
        exit 1
    }
    target="$t"
    echo "[+] Target: $target"
}

# ---------------------------------------------------------------
# Legacy controller: <target> <phase>
# ---------------------------------------------------------------

cmd_legacy() {
    local target="${1:-}"
    local phase="${2:-full}"

    get_target "$target"
    load_config
    check_dependencies "$phase"

    case "$phase" in
        discovery)
            phase_discovery
            ;;
        enumeration)
            phase_enumeration
            ;;
        vulnerability|vulnerabilities)
            phase_vulnerabilities
            ;;
        correlation)
            phase_correlation
            ;;
        exploit|exploitation)
            # Single-phase execution: exploitation ONLY. Evidence and
            # report are separate phases - they are never chained from a
            # single-phase command. See 'full' for the whole pipeline.
            EXP_RC=0
            phase_exploit || EXP_RC=$?
            echo
            echo "[+] Exploitation phase finished (exit code: $EXP_RC)."
            echo "    Evidence and report are separate phases; run them explicitly:"
            echo "      ./$0 $TARGET evidence"
            echo "      ./$0 $TARGET report"
            exit "$EXP_RC"
            ;;
        evidence)
            phase_evidence
            ;;
        report)
            phase_report
            ;;
        full)
            # Full pipeline: discovery -> enumeration -> vulnerabilities ->
            # correlation -> exploitation (explicit approval required) ->
            # evidence -> report. A pre-exploitation failure stops the chain
            # but still yields an honest report.
            PIPELINE_RC=0
            phase_discovery || PIPELINE_RC=$?
            if (( PIPELINE_RC == 0 )); then phase_enumeration || PIPELINE_RC=$?; fi
            if (( PIPELINE_RC == 0 )); then phase_vulnerabilities || PIPELINE_RC=$?; fi
            if (( PIPELINE_RC == 0 )); then phase_correlation || PIPELINE_RC=$?; fi
            if (( PIPELINE_RC == 0 )); then
                EXP_RC=0
                phase_exploit || EXP_RC=$?
                phase_evidence || true
                phase_report || true
                PIPELINE_RC=$EXP_RC
            else
                phase_report || true
            fi
            echo
            echo "[+] Full pipeline finished (rc=$PIPELINE_RC)."
            echo "    Phase 5 (exploitation) only ever ran with explicit in-run approval."
            echo "    Evidence and report reflect the actual exploitation result."
            exit "$PIPELINE_RC"
            ;;
        all)
            ALL_RC=0
            phase_discovery || ALL_RC=$?
            if (( ALL_RC == 0 )); then phase_enumeration || ALL_RC=$?; fi
            exit "$ALL_RC"
            ;;
        *)
            echo "[-] Unknown phase: $phase" >&2
            echo "    Supported: discovery, enumeration, vulnerabilities, correlation,"
            echo "               exploit, evidence, report, full" >&2
            exit 1
            ;;
    esac

    echo
    echo "[+] Pipeline complete (phase: $phase)."
}

# ---------------------------------------------------------------
# main
# ---------------------------------------------------------------

main() {
    print_banner

    local cmd="${1:-}"
    case "$cmd" in
        --help|-h|help|-help)
            cmd_help
            exit 0
            ;;
        scan)
            shift
            cmd_scan "$@"
            ;;
        status)
            shift
            cmd_status "$@"
            ;;
        resume)
            shift
            cmd_resume "$@"
            ;;
        preflight)
            shift
            cmd_preflight "$@"
            ;;
        report)
            shift
            cmd_report "$@"
            ;;
        scope)
            shift
            cmd_scope "$@"
            ;;
        history)
            shift
            cmd_history "$@"
            ;;
        compare)
            shift
            cmd_compare "$@"
            ;;
        menu)
            shift
            cmd_menu "$@"
            ;;
        *)
            cmd_legacy "$@"
            ;;
    esac
}

main "$@"