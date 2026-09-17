#!/usr/bin/env bash
#
# security-assessment test harness.
#
# Runs the numbered Phase 3-9 acceptance checks against deterministic
# fixtures and fake external tools, WITHOUT touching a live Metasploitable
# host or any real exploitdb/Metasploit installation.
#
# Usage:
#   ./tests/test_tool.sh            [--network] [--keep] [--verbose]
#
#   --network   also run host-reachability/enumeration tests against
#               localhost TEST-NET fixtures (requires loopback scan ports open)
#   --keep      keep per-test run logs under tests/runs/
#   --verbose   print the full log of a failing command
#
# Exit: 0 all tests passed, 1 otherwise.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAKES="$ROOT/tests/fakes"
FIXTURES="$ROOT/tests/fixtures"
MODULES="$ROOT/modules"
OUT="$ROOT/output"

MS2_XML="$FIXTURES/ms2_enum.xml"
CLEAN_XML="$FIXTURES/ms2_clean.xml"
CORRUPT_XML="$FIXTURES/corrupt.xml"

TARGET_MS2="203.0.113.7"     # TEST-NET-1 (RFC 5737) - never a real host
TARGET_CLEAN="203.0.113.8"
TARGET_NOART="198.51.100.7"  # TEST-NET-2
TARGET_NO_DATA="192.0.2.9"   # TEST-NET-1
TARGET_LOOP="127.0.0.1"

BASE_PATH="$PATH"
export PATH="$FAKES:$BASE_PATH"
export CONFIG_FILE="$FIXTURES/config.conf"

RUN_NETWORK=0
KEEP=0
VERBOSE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --network) RUN_NETWORK=1 ;;
        --keep) KEEP=1 ;;
        --verbose) VERBOSE=1 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

RUNBASE="$ROOT/tests/runs"
RUN_TS="$(date +%Y%m%d_%H%M%S)"
RUN="$RUNBASE/$RUN_TS"
mkdir -p "$RUN"

PASS=0
FAIL=0
SKIP=0
FAILED=()
LOGNO=0

note() { printf '%-76s ' "$1"; }

pass() { PASS=$((PASS + 1)); echo "PASS"; }

fail() {
    local why="$1" which="$2"
    FAIL=$((FAIL + 1)); FAILED+=("$which")
    echo "FAIL - $why"
}

skip_note() { SKIP=$((SKIP + 1)); echo "SKIP (see note)"; }

latest_dir() {
    # latest_dir <prefix> ; prints lexically-latest matching dir
    local d found=""
    for d in "$1"*; do
        [[ -d "$d" ]] && found="$d"
    done
    printf '%s' "$found"
}

# run_expect <desc> <expected_rc> <cmd...>
run_expect() {
    local desc="$1" exp="$2"
    shift 2
    LOGNO=$((LOGNO + 1))
    local log="$RUN/$LOGNO.log"
    note "$desc"
    "$@" >"$log" 2>&1
    local rc=$?
    if [[ "$rc" == "$exp" ]]; then
        pass
    else
        fail "expected rc=$exp, got rc=$rc" "$desc"
        if [[ "$VERBOSE" == 1 ]]; then
            echo "----- log: $log -----"
            sed -n '1,40p' "$log" | sed 's/^/    /'
        fi
    fi
}

# assert_file <desc> <path> [exists|nonempty|empty]
assert_file() {
    local desc="$1" path="$2" mode="${3:-nonempty}"
    note "$desc"
    if [[ ! -e "$path" ]]; then
        fail "file missing: $path" "$desc"
        return
    fi
    if [[ "$mode" == "nonempty" ]] && [[ ! -s "$path" ]]; then
        fail "file empty: $path" "$desc"
        return
    fi
    if [[ "$mode" == "empty" ]] && [[ -s "$path" ]]; then
        fail "file not empty: $path" "$desc"
        return
    fi
    pass
}

# assert_contains <desc> <needle> <path>
assert_contains() {
    local desc="$1" needle="$2" path="$3"
    note "$desc"
    if [[ -f "$path" ]] && grep -q -F -- "$needle" "$path"; then
        pass
    else
        fail "needle not found in $path: <$needle>" "$desc"
        if [[ "$VERBOSE" == 1 ]]; then
            echo "----- $path -----"
            sed -n '1,25p' "$path" | sed 's/^/    /'
        fi
    fi
}

# assert_not_contains <desc> <needle> <path>
assert_not_contains() {
    local desc="$1" needle="$2" path="$3"
    note "$desc"
    if [[ ! -f "$path" ]] || ! grep -q --fixed-strings "$needle" "$path"; then
        pass
    else
        fail "unexpected needle in $path: <$needle>" "$desc"
    fi
}

# assert_json_ok <desc> <path>
assert_json_ok() {
    local desc="$1" path="$2"
    note "$desc"
    if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$path" 2>/dev/null; then
        pass
    else
        fail "invalid JSON: $path" "$desc"
    fi
}

# assert_count <desc> <path> <count>    (non-header rows in a tsv)
assert_count() {
    local desc="$1" path="$2" want="$3"
    note "$desc"
    local got
    got=$(( $(wc -l < "$path") - 1 ))
    if [[ "$got" == "$want" ]]; then
        pass
    else
        fail "expected $want rows, got $got ($path)" "$desc"
    fi
}

# assert_xml_ok <desc> <path>
assert_xml_ok() {
    local desc="$1" path="$2"
    note "$desc"
    if python3 -c 'import sys,xml.etree.ElementTree as ET; ET.parse(sys.argv[1])' "$path" 2>/dev/null; then
        pass
    else
        fail "invalid XML: $path" "$desc"
    fi
}

# ------------------------------------------------------------------
# 01. Syntax / sanity checks
# ------------------------------------------------------------------

t01_syntax() {
    local f
    for f in lib/common.sh lib/assessment.sh lib/scope.sh lib/scope_worker.sh scanner.sh modules/*.sh modules/service_handlers/*.sh; do
        note "t01 bash -n $f"
        if bash -n "$f" >/dev/null 2>&1; then pass; else fail "syntax error in $f" "$f"; fi
    done
}

t02_executable() {
    local f
    for f in scanner.sh modules/*.sh modules/service_handlers/*.sh tests/fakes/*; do
        note "t02 executable $f"
        if [[ -x "$f" ]]; then pass; else fail "not executable: $f" "$f"; fi
    done
}

t03_safe_name() {
    local got exp
    got="$(bash -c 'source "$1"; sat_safe_name "$2"' _ "$ROOT/lib/common.sh" "10.0.0.1;rm -rf")"
    exp="10.0.0.1_rm_-rf_"
    if [[ "$got" == *"_"* && "$got" != *";"* && "$got" != *" "* ]]; then
        note "t03 sat_safe_name sanitizes metacharacters"
        pass
    else
        note "t03 sat_safe_name '10.0.0.1;rm -rf' -> '$got'"
        fail "unsanitized output" "$got"
    fi
}

t04_invalid_targets() {
    run_expect "t04a vuln empty target rc=1" 1 env PATH="$BASE_PATH" "$MODULES/vulnerability.sh"
    run_expect "t04b corr empty target rc=1" 1 env PATH="$BASE_PATH" "$MODULES/correlation.sh" ""
    run_expect "t04c exploit empty target rc=1" 1 env PATH="$BASE_PATH" "$MODULES/exploitation.sh" ""
    run_expect "t04d evidence empty target rc=1" 1 env PATH="$BASE_PATH" "$MODULES/evidence.sh" ""
    run_expect "t04e report empty target rc=1" 1 env PATH="$BASE_PATH" "$MODULES/report.sh" ""
    run_expect "t04f vuln option-injection target rc=1" 1 env PATH="$BASE_PATH" "$MODULES/vulnerability.sh" "-oX"
    run_expect "t04g vuln command-injection target rc=1" 1 env PATH="$BASE_PATH" "$MODULES/vulnerability.sh" "203.0.113.7;echo pwned"
    LOGNO=$((LOGNO + 1))
    note "t04h vuln usage text printed"
    env PATH="$BASE_PATH" "$MODULES/vulnerability.sh" >"$RUN/$LOGNO.log" 2>&1
    if grep -q "Usage:" "$RUN/$LOGNO.log"; then pass; else fail "usage text missing" "usage"; fi
}

# ------------------------------------------------------------------
# 02. Missing-dependency handling (real PATH, no fakes)
# ------------------------------------------------------------------

t05_searchsploit_missing() {
    run_expect "t05 vuln without searchsploit rc=3" 3 \
        env PATH="$BASE_PATH" "$MODULES/vulnerability.sh" "$TARGET_MS2"
    local d
    d="$(latest_dir "$OUT/vulnerabilities/${TARGET_MS2}")"
    assert_contains "t05 status dependency-missing" "status=dependency-missing" "$d/status.txt"
}

t06_msfconsole_missing() {
    run_expect "t06 exploit without msfconsole rc=3" 3 \
        env PATH="$BASE_PATH" "$MODULES/exploitation.sh" "$TARGET_MS2"
    local d
    d="$(latest_dir "$OUT/exploitation/${TARGET_MS2}")"
    assert_contains "t06 status dependency-missing" "dependency=msfconsole" "$d/status.txt"
}

# ------------------------------------------------------------------
# 03. Enumeration XML handling
# ------------------------------------------------------------------

t07_corrupt_xml() {
    run_expect "t07 corrupt XML rc=1" 1 \
        env PATH="$FAKES:$BASE_PATH" "$MODULES/vulnerability.sh" "$TARGET_MS2" "$CORRUPT_XML"
}

t08_no_xml() {
    run_expect "t08 no enumeration XML rc=2" 2 \
        env PATH="$FAKES:$BASE_PATH" "$MODULES/vulnerability.sh" "$TARGET_NOART"
}

# ------------------------------------------------------------------
# 04. Clean target (no matching candidates) - honest zero findings
# ------------------------------------------------------------------

t09_clean_target() {
    run_expect "t09a vuln clean target rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" "$MODULES/vulnerability.sh" "$TARGET_CLEAN" "$CLEAN_XML"
    local d
    d="$(latest_dir "$OUT/vulnerabilities/${TARGET_CLEAN}")"
    assert_contains "t09a status candidates=0" "candidates=0" "$d/status.txt"
    assert_contains "t09a summary honest" "Exploit candidates captured: 0" "$d/summary.txt"

    run_expect "t09b correlation clean target rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" "$MODULES/correlation.sh" "$TARGET_CLEAN"
    local c
    c="$(latest_dir "$OUT/vulnerabilities/${TARGET_CLEAN}")"
    assert_contains "t09b status findings=0" "findings=0" "$c/status.txt"
    assert_file "t09b correlated_findings.tsv header-only" "$c/correlated_findings.tsv" nonempty
    assert_count "t09b zero finding rows" "$c/correlated_findings.tsv" 0
}

# ------------------------------------------------------------------
# 05. Vulnerable fixture target - phases 3..7 positive path
# ------------------------------------------------------------------

t10_vulnerability() {
    run_expect "t10 vuln ms2 fixture rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" "$MODULES/vulnerability.sh" "$TARGET_MS2" "$MS2_XML"
    local d
    d="$(latest_dir "$OUT/vulnerabilities/${TARGET_MS2}")"
    assert_file "t10 services.tsv" "$d/services.tsv"
    assert_file "t10 services.txt" "$d/services.txt"
    assert_file "t10 exploitdb_candidates.tsv" "$d/exploitdb_candidates.tsv"
    assert_file "t10 findings.json" "$d/findings.json"
    assert_file "t10 summary.txt" "$d/summary.txt"
    assert_file "t10 status.txt" "$d/status.txt"
    assert_json_ok "t10 findings.json valid JSON" "$d/findings.json"
    assert_contains "t10 status completed" "status=completed" "$d/status.txt"
    assert_contains "t10 status candidates=3" "candidates=3" "$d/status.txt"
    assert_contains "t10 candidate vsftpd" "17491" "$d/exploitdb_candidates.tsv"
    assert_contains "t10 candidate samba" "16320" "$d/exploitdb_candidates.tsv"
}

t11_correlation() {
    run_expect "t11 correlation ms2 fixture rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" "$MODULES/correlation.sh" "$TARGET_MS2"
    local d
    d="$(latest_dir "$OUT/vulnerabilities/${TARGET_MS2}")"
    assert_file "t11 correlated_findings.tsv" "$d/correlated_findings.tsv"
    assert_file "t11 findings.json" "$d/findings.json"
    assert_file "t11 findings.txt" "$d/findings.txt"
    assert_file "t11 summary.txt" "$d/summary.txt"
    assert_json_ok "t11 findings.json valid JSON" "$d/findings.json"
    assert_contains "t11 status completed" "status=completed" "$d/status.txt"
    assert_contains "t11 findings=3" "findings=3" "$d/status.txt"
    assert_contains "t11 findings_high=1 vsftpd exact" "findings_high=1" "$d/status.txt"
    assert_contains "t11 findings_medium=2 samba major.minor" "findings_medium=2" "$d/status.txt"
    assert_count "t11 finding rows" "$d/correlated_findings.tsv" 3
    assert_contains "t11 summary findings total" "Findings total: 3" "$d/findings.txt"
    assert_contains "t11 severity honest (not CVSS)" "not CVSS" "$d/summary.txt"
}

t12_exploit_denied() {
    run_expect "t12 exploit denied rc=5" 5 \
        bash -c 'printf "1\nn\n" | "$0" 203.0.113.7' "$MODULES/exploitation.sh"
    LOGNO=$((LOGNO + 1))
    note "t12 no exploitation output on denial"
    if ls -1dt "$OUT"/exploitation/${TARGET_MS2}_* >/dev/null 2>&1 && \
       [[ -f "$(latest_dir "$OUT/exploitation/${TARGET_MS2}")/result.txt" ]] \
       && grep -q 'status=' "$(latest_dir "$OUT/exploitation/${TARGET_MS2}")/status.txt"; then
        fail "denial still produced an exploitation result" "t12 no result"
    else
        pass
    fi
}

t13_exploit_no_session() {
    run_expect "t13 exploit no-session rc=2" 2 \
        bash -c 'printf "2\ny\n" | "$0" 203.0.113.7' "$MODULES/exploitation.sh"
    local d
    d="$(latest_dir "$OUT/exploitation/${TARGET_MS2}")"
    assert_contains "t13 status no-session" "status=no-session" "$d/status.txt"
    assert_contains "t13 result no-session" "session_status=no-session" "$d/result.txt"
    assert_contains "t13 selected samba module" "usermap_script" "$d/result.txt"
    assert_file "t13 exploit_output.txt preserved" "$d/exploit_output.txt"
    assert_file "t13 msf_resource.res preserved" "$d/msf_resource.res"
    NO_SESSION_DIR="$d"
}

t14_exploit_session() {
    run_expect "t14 exploit session rc=0" 0 \
        bash -c 'printf "1\ny\n" | "$0" 203.0.113.7' "$MODULES/exploitation.sh"
    local d
    d="$(latest_dir "$OUT/exploitation/${TARGET_MS2}")"
    assert_contains "t14 status session-created" "status=session-created" "$d/status.txt"
    assert_contains "t14 result session-created" "session_status=session-created" "$d/result.txt"
    assert_contains "t14 session id" "session_id=1" "$d/result.txt"
    assert_contains "t14 selected vsftpd module" "vsftpd_234_backdoor" "$d/result.txt"
    assert_contains "t14 evidence markers collected" "SAT_EVIDENCE_END" "$d/exploit_output.txt"
    SESSION_DIR="$d"
}

# ------------------------------------------------------------------
# 06. Evidence phase (explicitly bound to a given exploitation dir)
# ------------------------------------------------------------------

t15_evidence_session() {
    run_expect "t15 evidence session rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" "$MODULES/evidence.sh" "$TARGET_MS2" "$SESSION_DIR"
    local d
    d="$(latest_dir "$OUT/evidence/${TARGET_MS2}")"
    assert_contains "t15 status session-created" "status=session-created" "$d/status.txt"
    assert_contains "t15 session.txt" "session_status=session-created" "$d/session.txt"
    assert_file "t15 metadata.txt" "$d/metadata.txt"
    assert_json_ok "t15 metadata.json valid JSON" "$d/metadata.json"
    assert_file "t15 system_info.raw.txt" "$d/system_info.raw.txt"
    assert_contains "t15 hostname evidence" "metasploitable" "$d/system_info.raw.txt"
    assert_contains "t15 network evidence" "203.0.113.7" "$d/network_info.raw.txt" 2>/dev/null || true
}

t16_evidence_no_session() {
    run_expect "t16 evidence no-session rc=2" 2 \
        env PATH="$FAKES:$BASE_PATH" "$MODULES/evidence.sh" "$TARGET_MS2" "$NO_SESSION_DIR"
    local d
    local latest=""
    d="$(latest_dir "$OUT/evidence/${TARGET_MS2}")"
    assert_contains "t16 session.txt no-session" "session_status=no-session" "$d/session.txt"
    assert_contains "t16 metadata honest note" "no system evidence collected" "$d/metadata.txt"
}

# ------------------------------------------------------------------
# 07. Reporting
# ------------------------------------------------------------------

t17_report_full() {
    run_expect "t17 report full fixture rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" "$MODULES/report.sh" "$TARGET_MS2"
    local f
    f="$(ls -1dt "$ROOT"/reports/${TARGET_MS2}_*.md 2>/dev/null | head -n1)"
    assert_file "t17 markdown report" "$f"
    assert_contains "t17 has exec summary" "## 1. Executive Summary" "$f"
    assert_contains "t17 has correlated findings" "## 7. Correlated Findings" "$f"
    assert_contains "t17 has exploitation results" "## 9. Exploitation Results" "$f"
    assert_contains "t17 vsftpd finding" "vsftpd" "$f"
    assert_contains "t17 session created noted" "session was created" "$f"
    local h
    h="$(ls -1dt "$ROOT"/reports/${TARGET_MS2}_*.html 2>/dev/null | head -n1)"
    assert_file "t17 html report" "$h"
}

t18_report_partial() {
    # Hermetic partial assessment: run Phase 2 against the loopback target (fake
    # nmap, offline) into a scratch worktree, then confirm the report marks the
    # unexecuted phases honestly. No dependency on leftover run artifacts.
    local wrk="$RUN/t18_work"
    local enum_dir="$wrk/enumeration"
    local report_dir="$wrk/reports"
    mkdir -p "$enum_dir" "$report_dir"
    run_expect "t18 phase2 loopback (fake) rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$enum_dir" FAKE_NMAP_UP=1 \
            "$MODULES/enumeration.sh" "$TARGET_LOOP"
    run_expect "t18 report partial (loopback enum only) rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$enum_dir" OUTPUT_REPORTS="$report_dir" \
            "$MODULES/report.sh" "$TARGET_LOOP"
    local f
    f="$(ls -1dt ${report_dir}/${TARGET_LOOP}_*.md 2>/dev/null | head -n1)"
    assert_file "t18 markdown report" "$f"
    assert_contains "t18 open ports section" "## 4. Open Ports" "$f"
    assert_contains "t18 not-performed honesty" "not performed" "$f"
}

t19_report_no_data() {
    run_expect "t19 report no data rc=2" 2 \
        env PATH="$FAKES:$BASE_PATH" "$MODULES/report.sh" "$TARGET_NO_DATA"
}

# ------------------------------------------------------------------
# 08. Unexpected external-tool output (garbage) must not crash
# ------------------------------------------------------------------

t20_garbage_output() {
    run_expect "t20 garbage searchsploit rc=0" 0 \
        env FAKE_MODE=garbage PATH="$FAKES:$BASE_PATH" \
        "$MODULES/vulnerability.sh" "$TARGET_MS2" "$MS2_XML"
    local d
    d="$(latest_dir "$OUT/vulnerabilities/${TARGET_MS2}")"
    assert_contains "t20 garbage handled, candidates=0" "candidates=0" "$d/status.txt"
    assert_contains "t20 completed anyway" "status=completed" "$d/status.txt"
}

# ------------------------------------------------------------------
# 08. Phase 8 - scanner orchestration integration
# ------------------------------------------------------------------

t26_scanner_usage() {
    run_expect "t26a scanner invalid target rc=1" 1 \
        timeout 30 env PATH="$FAKES:$BASE_PATH" "$ROOT/scanner.sh" "-oX"
    run_expect "t26b scanner unknown phase rc=1" 1 \
        timeout 30 env PATH="$FAKES:$BASE_PATH" "$ROOT/scanner.sh" "$TARGET_MS2" "nonsense"
}

t27_scanner_all_unreachable() {
    run_expect "t27 scanner all on unreachable rc=2" 2 \
        timeout 90 env PATH="$FAKES:$BASE_PATH" "$ROOT/scanner.sh" "203.0.113.99" "all"
}

t28_scanner_exploit_chain() {
    # Exploitation read from empty stdin -> cancelled (5); evidence and
    # report still run and produce honest "not performed"/no-result state.
    run_expect "t28 scanner exploit chain rc=5 (cancelled)" 5 \
        timeout 60 bash -c '"$0" "$1" exploit < /dev/null' \
        "$ROOT/scanner.sh" "$TARGET_MS2"
}

t29_scanner_report() {
    run_expect "t29 scanner report rc=0" 0 \
        timeout 60 env PATH="$FAKES:$BASE_PATH" "$ROOT/scanner.sh" "$TARGET_MS2" "report"
}

# ------------------------------------------------------------------
# 09. Network-gated host behavior (optional)
# ------------------------------------------------------------------

t21_discovery_metadata() {
    note "t21 scanner help/run metadata"
    local out
    out="$(env PATH="$FAKES:$BASE_PATH" "$MODULES/exploitation.sh" "$TARGET_MS2" 2>&1 <<< "" || true)"
    if printf '%s' "$out" | grep -qE 'Usage:|AUTO_EXPLOIT|REQUIRE_EXPLOIT_APPROVAL|No input available'; then
        pass
    else
        fail "no readable behavior for empty input" "t21"
    fi
}

t22_unreachable() {
    run_expect "t22 enumeration unreachable host rc=2" 2 \
        timeout 70 env PATH="$BASE_PATH" NMAP_PORTS="-p 58000" \
        "$MODULES/enumeration.sh" "203.0.113.99"
}

t23_no_open_ports() {
    run_expect "t23 reachable but no open ports rc=3" 3 \
        timeout 80 env PATH="$BASE_PATH" NMAP_PORTS="-p 58000,58001,58003,58005" \
        NMAP_SCRIPTS="banner" "$MODULES/enumeration.sh" "$TARGET_LOOP"
}

t24_open_ports() {
    run_expect "t24 loopback enumeration rc=0" 0 \
        timeout 80 env PATH="$BASE_PATH" NMAP_PORTS="-p 631,3306" \
        NMAP_SCRIPTS="banner" "$MODULES/enumeration.sh" "$TARGET_LOOP"
    local f
    f="$(ls -1dt "$OUT"/enumeration/${TARGET_LOOP}_*.xml 2>/dev/null | head -n1)"
    assert_xml_ok "t24 XML parses (python ET)" "$f"
}

# ------------------------------------------------------------------
# 10. Repeated execution does not clobber prior results
# ------------------------------------------------------------------

t25_no_clobber() {
    local before after
    before="$(ls -1dt "$OUT"/vulnerabilities/${TARGET_MS2}_* 2>/dev/null | wc -l)"
    run_expect "t25 re-run vulnerability rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" "$MODULES/vulnerability.sh" "$TARGET_MS2" "$MS2_XML"
    after="$(ls -1dt "$OUT"/vulnerabilities/${TARGET_MS2}_* 2>/dev/null | wc -l)"
    note "t25 both runs retained (new dir created)"
    if [[ -n "$before" ]] && (( after > before )); then pass; else fail "new artifact dir not created (before=$before after=$after)" "t25"; fi
}

# ------------------------------------------------------------------
# 11. Assessment manager / unified CLI / single-phase rule
# ------------------------------------------------------------------
# Every UX test runs inside its own scratch dir (ASSESSMENTS_ROOT and
# OUTPUT_* are passed via `ux`, never exported) so no state leaks into
# the phase tests above or into the repo's real output/.

# ux <scratch> <cmd...> - run command with isolated assessment/output dirs.
ux() {
    local s="$1"
    shift
    env \
        ASSESSMENTS_ROOT="$s/assessments" \
        OUTPUT_NMAP="$s/nmap" \
        OUTPUT_ENUM="$s/enum" \
        OUTPUT_VULN="$s/vuln" \
        OUTPUT_EXPLOIT="$s/exploit" \
        OUTPUT_EVIDENCE="$s/evidence" \
        OUTPUT_REPORTS="$s/reports" \
        PATH="$FAKES:$BASE_PATH" \
        FAKE_NMAP_UP=1 \
        "$@"
}

# manifest_status <desc> <manifest> <want-status>
manifest_status() {
    note "$1"
    if python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); sys.exit(0 if m.get("status")==sys.argv[2] else 1)' "$2" "$3"; then
        pass
    else
        fail "status != $3 in $2" "$1"
    fi
}

# manifest_has_phase <desc> <manifest> <phase>
manifest_has_phase() {
    note "$1"
    if python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); sys.exit(0 if sys.argv[2] in m.get("completed_phases",[]) else 1)' "$2" "$3"; then
        pass
    else
        fail "phase '$3' not completed in $2" "$1"
    fi
}

# manifest_no_phase <desc> <manifest> <phase>
manifest_no_phase() {
    note "$1"
    if python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); sys.exit(1 if sys.argv[2] in m.get("completed_phases",[]) else 0)' "$2" "$3"; then
        pass
    else
        fail "phase '$3' unexpectedly completed in $2" "$1"
    fi
}

t30_ux_helpers() {
    local s="$RUN/t30"
    mkdir -p "$s"
    # nanosecond-based unique ids (nothing is created on a dry run)
    local log1="$RUN/t30_dry1.log" log2="$RUN/t30_dry2.log" id1 id2
    ux "$s" "$ROOT/scanner.sh" scan "$TARGET_MS2" --dry-run >"$log1" 2>&1
    ux "$s" "$ROOT/scanner.sh" scan "$TARGET_MS2" --dry-run >"$log2" 2>&1
    id1="$(sed -n 's/.*Would create assessment: //p' "$log1" | head -1)"
    id2="$(sed -n 's/.*Would create assessment: //p' "$log2" | head -1)"
    note "t30 dry-run prints assessment id"
    if [[ "$id1" == assessment_* ]] && [[ "$id2" == assessment_* ]]; then pass; else fail "no id printed" "t30 id"; fi
    note "t30 ids are unique"
    [[ -n "$id1" && -n "$id2" && "$id1" != "$id2" ]] && pass || fail "$id1 vs $id2" "t30 unique"
    note "t30 dry-run creates nothing"
    if [[ -z "$(ls -A "$s" 2>/dev/null)" ]]; then pass; else fail "dry run modified scratch" "t30 dryrun"; fi
}

t31_single_phase_exploit() {
    local s="$RUN/t31"
    mkdir -p "$s"
    # Build the standalone prerequisite tree so that IF the exploit command
    # wrongly chained evidence/report it would have everything it needed.
    ux "$s" timeout 90 "$ROOT/scanner.sh" "$TARGET_MS2" all >/dev/null 2>&1
    ux "$s" timeout 90 "$ROOT/scanner.sh" "$TARGET_MS2" vulnerabilities >/dev/null 2>&1
    ux "$s" timeout 90 "$ROOT/scanner.sh" "$TARGET_MS2" correlation >/dev/null 2>&1

    run_expect "t31 CLI 'exploit' runs only exploitation (rc=0)" 0 \
        ux "$s" timeout 90 bash -c 'printf "1\ny\n" | "$0" 203.0.113.7 exploit' "$ROOT/scanner.sh"
    local xdir
    xdir="$(latest_dir "$s/exploit/${TARGET_MS2}")"
    assert_file "t31 exploitation result.txt" "$xdir/result.txt"
    assert_contains "t31 session created" "session_status=session-created" "$xdir/result.txt"

    note "t31 no evidence phase produced"
    if [[ -z "$(latest_dir "$s/evidence/${TARGET_MS2}" 2>/dev/null)" ]]; then pass; else fail "evidence unexpectedly produced" "t31 evidence"; fi
    note "t31 no report phase produced"
    if [[ -z "$(ls -1 "$s/reports/${TARGET_MS2}"_*.md 2>/dev/null)" ]]; then pass; else fail "report unexpectedly produced" "t31 report"; fi
}

t32_single_phase_enumeration() {
    local s="$RUN/t32"
    mkdir -p "$s"
    run_expect "t32 CLI 'enumeration' runs only enumeration (rc=0)" 0 \
        ux "$s" timeout 90 "$ROOT/scanner.sh" "$TARGET_MS2" enumeration
    local f
    f="$(ls -1dt "$s/enum/${TARGET_MS2}"_*.xml 2>/dev/null | head -n1)"
    assert_file "t32 enumeration xml produced" "$f"
    assert_xml_ok "t32 enumeration xml valid" "$f"
    note "t32 no vulnerability output produced"
    if [[ -z "$(latest_dir "$s/vuln/${TARGET_MS2}" 2>/dev/null)" ]]; then pass; else fail "vulnerability output unexpectedly produced" "t32 vuln"; fi
    note "t32 no assessment created"
    if [[ -z "$(ls -A "$s/assessments" 2>/dev/null)" ]]; then pass; else fail "assessment unexpectedly created" "t32 assess"; fi
}

t33_menu_single_phase() {
    local s="$RUN/t33"
    mkdir -p "$s"
    # Prerequisite standalone tree (same as t31) so a wrongly-chained
    # menu selection would have everything available to it.
    ux "$s" timeout 90 "$ROOT/scanner.sh" "$TARGET_MS2" all >/dev/null 2>&1
    ux "$s" timeout 90 "$ROOT/scanner.sh" "$TARGET_MS2" vulnerabilities >/dev/null 2>&1
    ux "$s" timeout 90 "$ROOT/scanner.sh" "$TARGET_MS2" correlation >/dev/null 2>&1

    # 8=exploitation, then target, select vsftpd, approve, then 0=exit.
    note "t33 menu option 8 (exploitation) returns to the menu"
    printf '8\n203.0.113.7\n1\ny\n0\n' | ux "$s" timeout 120 "$ROOT/scanner.sh" menu >"$s/menu.log" 2>&1
    local rc=$?
    if [[ "$rc" == 0 ]]; then pass; else fail "menu rc=$rc" "t33 menu rc"; fi
    assert_contains "t33 menu looped back (Goodbye printed)" "[+] Goodbye." "$s/menu.log"
    local xdir
    xdir="$(latest_dir "$s/exploit/${TARGET_MS2}")"
    assert_file "t33 exploitation result.txt" "$xdir/result.txt"
    note "t33 menu did not chain evidence/report"
    if [[ -z "$(latest_dir "$s/evidence/${TARGET_MS2}" 2>/dev/null)" ]] \
       && [[ -z "$(ls -1 "$s/reports/${TARGET_MS2}"_*.md 2>/dev/null)" ]]; then
        pass
    else
        fail "menu selection chained extra phases" "t33 chain"
    fi
}

t34_full_pipeline_approved() {
    local s="$RUN/t34"
    mkdir -p "$s"
    run_expect "t34 legacy 'full' + approved exploit rc=0" 0 \
        ux "$s" timeout 150 bash -c 'printf "1\ny\n" | "$0" 203.0.113.7 full' "$ROOT/scanner.sh"
    local d
    d="$(latest_dir "$s/nmap/${TARGET_MS2}")"
    assert_file "t34 discovery txt" "$(ls -1dt "$s/nmap/${TARGET_MS2}"_*.txt 2>/dev/null | head -n1)"
    assert_file "t34 enumeration xml" "$(ls -1dt "$s/enum/${TARGET_MS2}"_*.xml 2>/dev/null | head -n1)"
    d="$(latest_dir "$s/vuln/${TARGET_MS2}")"
    assert_file "t34 correlation findings" "$d/correlated_findings.tsv"
    d="$(latest_dir "$s/exploit/${TARGET_MS2}")"
    assert_contains "t34 exploitation session" "session_status=session-created" "$d/result.txt"
    d="$(latest_dir "$s/evidence/${TARGET_MS2}")"
    assert_contains "t34 evidence session" "session_status=session-created" "$d/session.txt"
    local r
    r="$(ls -1dt "$s/reports/${TARGET_MS2}"_*.md 2>/dev/null | head -n1)"
    assert_file "t34 report md" "$r"
    assert_contains "t34 report notes session" "session was created" "$r"
}

t35_full_pipeline_declined() {
    local s="$RUN/t35"
    mkdir -p "$s"
    run_expect "t35 legacy 'full' + declined exploit rc=5" 5 \
        ux "$s" timeout 150 bash -c 'printf "1\nn\n" | "$0" 203.0.113.7 full' "$ROOT/scanner.sh"
    note "t35 denial left no exploitation result"
    if [[ -z "$(latest_dir "$s/exploit/${TARGET_MS2}" 2>/dev/null)" ]]; then
        pass
    else
        fail "exploitation result created despite denial" "t35 denies"
    fi
    note "t35 no evidence artifacts without a result to copy"
    if [[ -z "$(ls -1 "$s/evidence" 2>/dev/null)" ]]; then
        pass
    else
        fail "evidence artifacts created without an exploitation result" "t35 evidence"
    fi
    local r
    r="$(ls -1dt "$s/reports/${TARGET_MS2}"_*.md 2>/dev/null | head -n1)"
    assert_file "t35 honest report still written" "$r"
    assert_contains "t35 report says exploitation not performed" "not performed" "$r"
}

t36_scan_full_approved() {
    local s="$RUN/t36"
    mkdir -p "$s"
    run_expect "t36 scan --full + approved exploit rc=0" 0 \
        ux "$s" timeout 160 bash -c 'printf "1\ny\n" | "$0" scan 203.0.113.7 --full' "$ROOT/scanner.sh"
    local aid m
    aid="$(ls -1dt "$s/assessments"/assessment_* 2>/dev/null | head -n1 | xargs basename)"
    assert_file "t36 manifest exists" "$s/assessments/$aid/manifest.json"
    m="$s/assessments/$aid/manifest.json"
    manifest_status "t36 status completed" "$m" completed
    manifest_has_phase "t36 discovery done" "$m" discovery
    manifest_has_phase "t36 enumeration done" "$m" enumeration
    manifest_has_phase "t36 vulnerabilities done" "$m" vulnerabilities
    manifest_has_phase "t36 correlation done" "$m" correlation
    manifest_has_phase "t36 exploitation done" "$m" exploitation
    manifest_has_phase "t36 evidence done" "$m" evidence
    manifest_has_phase "t36 report done" "$m" report
    assert_file "t36 assessment report md" "$(ls -1dt "$s/assessments/$aid/report/"*_*.md 2>/dev/null | head -n1)"
}

t37_scan_quick_resume() {
    local s="$RUN/t37"
    mkdir -p "$s"
    run_expect "t37 scan --quick rc=0" 0 \
        ux "$s" timeout 90 "$ROOT/scanner.sh" scan "$TARGET_MS2" --quick
    local aid m
    aid="$(ls -1dt "$s/assessments"/assessment_* 2>/dev/null | head -n1 | xargs basename)"
    m="$s/assessments/$aid/manifest.json"
    manifest_status "t37 quick status completed" "$m" completed
    manifest_has_phase "t37 quick discovery done" "$m" discovery
    manifest_has_phase "t37 quick enumeration done" "$m" enumeration
    manifest_no_phase "t37 quick report NOT run" "$m" report

    note "t37 resume --dry-run prints remaining phases"
    ux "$s" timeout 60 "$ROOT/scanner.sh" resume "$aid" --dry-run >"$s/resume_dry.log" 2>&1
    if grep -q "vulnerabilities" "$s/resume_dry.log" \
       && grep -q "correlation" "$s/resume_dry.log" \
       && grep -q "report" "$s/resume_dry.log"; then
        pass
    else
        fail "resume dry-run plan missing phases" "t37 dryplan"
    fi
    note "t37 resume --dry-run executed nothing"
    if [[ -z "$(ls -1 "$s/assessments/$aid/vulnerabilities" 2>/dev/null)" ]]; then pass; else fail "vulnerabilities produced artifacts during dry run" "t37 dryrun"; fi

    run_expect "t37 resume completes remaining phases rc=0" 0 \
        ux "$s" timeout 120 "$ROOT/scanner.sh" resume "$aid"
    manifest_status "t37 resumed status completed" "$m" completed
    manifest_has_phase "t37 resumed vulnerabilities" "$m" vulnerabilities
    manifest_has_phase "t37 resumed correlation" "$m" correlation
    manifest_has_phase "t37 resumed report" "$m" report
    assert_file "t37 resumed assessment report md" "$(ls -1dt "$s/assessments/$aid/report/"*_*.md 2>/dev/null | head -n1)"
}

t38_status() {
    local s="$RUN/t38"
    mkdir -p "$s"
    note "t38 status with no assessments rc=0"
    ux "$s" timeout 30 "$ROOT/scanner.sh" status >"$s/empty.log" 2>&1
    local rc=$?
    if [[ "$rc" == 0 ]]; then
        pass
    else
        fail "status rc=$rc" "t38 none rc"
    fi
    assert_contains "t38 status reports (none)" "(none)" "$s/empty.log"

    ux "$s" timeout 90 "$ROOT/scanner.sh" scan "$TARGET_MS2" --quick >/dev/null 2>&1
    local aid
    aid="$(ls -1dt "$s/assessments"/assessment_* 2>/dev/null | head -n1 | xargs basename)"
    note "t38 status shows assessment in list"
    ux "$s" timeout 30 "$ROOT/scanner.sh" status >"$s/list.log" 2>&1
    if grep -q "$aid" "$s/list.log"; then pass; else fail "assessment not listed" "t38 list"; fi
    note "t38 status detail shows completed phases"
    ux "$s" timeout 30 "$ROOT/scanner.sh" status "$aid" >"$s/detail.log" 2>&1
    local body
    body="$(sed -n '/phase.*state/,$p' "$s/detail.log")"
    if grep -q "discovery" <<<"$body" && grep -q "completed" <<<"$body"; then
        pass
    else
        fail "detail state missing" "t38 detail"
    fi
}

t39_preflight() {
    local s="$RUN/t39"
    mkdir -p "$s"
    run_expect "t39 preflight (fakes present) rc=0" 0 \
        ux "$s" timeout 30 "$ROOT/scanner.sh" preflight "$TARGET_MS2"
    local log="$s/pre.log"
    ux "$s" timeout 30 "$ROOT/scanner.sh" preflight "$TARGET_MS2" >"$log" 2>&1
    assert_contains "t39 preflight confirms availability" "[+] Preflight OK" "$log"
}

t40_corrupt_manifest() {
    local s="$RUN/t40"
    mkdir -p "$s/assessments/assessment_bad"
    printf '{ oops\n' > "$s/assessments/assessment_bad/manifest.json"
    run_expect "t40 resume corrupt manifest rc=1" 1 \
        ux "$s" timeout 30 "$ROOT/scanner.sh" resume assessment_bad
    run_expect "t40 resume unknown id rc=1" 1 \
        ux "$s" timeout 30 "$ROOT/scanner.sh" resume assessment_missing
    LOGNO=$((LOGNO + 1))
    note "t40 corrupt manifest refusal message"
    ux "$s" timeout 30 "$ROOT/scanner.sh" resume assessment_bad >"$RUN/$LOGNO.log" 2>&1
    if grep -q "refusing to fabricate state" "$RUN/$LOGNO.log"; then
        pass
    else
        fail "no refusal message" "t40 refuse"
    fi
}

# ------------------------------------------------------------------
# 12. Enumeration V2 - multi-stage pipeline (offline, fake nmap)
# ------------------------------------------------------------------

# enums_at <base> <ts-marker> - return newest enumeration base prefix dir path
enum_v2_txt() {
    # newest <safe>_* .txt artifact (stage-2) for the target in $1 dir
    local dir="$1" safe="$2"
    ls -1dt "${dir}/${safe}_"*.txt 2>/dev/null | head -n1
}

t41_enum_v2_normal() {
    local s="$RUN/t41"
    mkdir -p "$s/enum"
    run_expect "t41 enumeration v2 rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$s/enum" FAKE_NMAP_UP=1 \
            "$MODULES/enumeration.sh" "$TARGET_MS2"

    local st tsv x t
    st="$(ls -1dt "$s/enum/${TARGET_MS2}_"*.status.txt 2>/dev/null | head -n1)"
    assert_file "t41 status file" "$st"
    assert_contains "t41 status completed" "status=completed" "$st"

    tsv="$(ls -1dt "$s/enum/${TARGET_MS2}_"*.services.tsv 2>/dev/null | head -n1)"
    assert_file "t41 services tsv" "$tsv"
    assert_count "t41 exactly one open service" "$tsv" 1

    x="$(ls -1dt "$s/enum/${TARGET_MS2}_"*.xml 2>/dev/null | grep -v '\.ports\.xml$' | head -n1)"
    assert_xml_ok "t41 stage-2 XML parses (python ET)" "$x"

    if [[ -f "$tsv" ]] && grep -q "vsftpd" "$tsv" && grep -q "21" "$tsv"; then
        note "t41 services.tsv carries service/product data"
        pass
    else
        fail "services.tsv missing service/product data" "t41 tsv data"
    fi

    local htsv
    htsv="$(ls -1dt "$s/enum/${TARGET_MS2}_"*.stage3/handlers.tsv 2>/dev/null | head -n1)"
    assert_file "t41 stage-3 handlers audit" "$htsv"
    assert_contains "t41 banner handler ran ok" "banner_store_handler" "$htsv"
}

t42_enum_v2_no_open() {
    local s="$RUN/t42"
    mkdir -p "$s/enum"
    run_expect "t42 reachable no open ports rc=3" 3 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$s/enum" FAKE_NMAP_NO_OPEN=1 \
            "$MODULES/enumeration.sh" "$TARGET_MS2"
    local st
    st="$(ls -1dt "$s/enum/${TARGET_MS2}_"*.status.txt 2>/dev/null | head -n1)"
    assert_file "t42 status file written" "$st"
    assert_contains "t42 status completed-no-open" "status=completed-no-open-ports" "$st"
    note "t42 no stage-2 artifact created"
    if ! ls -1 "$s/enum/${TARGET_MS2}_"*.xml 2>/dev/null | grep -qEv '\.ports\.xml$'; then
        pass
    else
        fail "stage-2 XML unexpectedly written" "t42 stage2"
    fi
}

t43_enum_v2_malformed_xml() {
    local s="$RUN/t43"
    mkdir -p "$s/enum"
    run_expect "t43 malformed XML rc=0 (still completes off text)" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$s/enum" FAKE_NMAP_UP=1 FAKE_NMAP_CORRUPT=1 \
            "$MODULES/enumeration.sh" "$TARGET_MS2"
    local st diag tsv
    st="$(ls -1dt "$s/enum/${TARGET_MS2}_"*.status.txt 2>/dev/null | head -n1)"
    assert_file "t43 status file written" "$st"
    assert_contains "t43 status partial (honest)" "status=partial" "$st"
    assert_contains "t43 parse fell back to text" "stage2_parse=txt-fallback" "$st"
    tsv="$(ls -1dt "$s/enum/${TARGET_MS2}_"*.services.tsv 2>/dev/null | head -n1)"
    assert_file "t43 services from text fallback" "$tsv"
    assert_count "t43 services parsed from text" "$tsv" 1
    diag="$(ls -1dt "$s/enum/${TARGET_MS2}_"*.diagnostics.log 2>/dev/null | head -n1)"
    assert_file "t43 diagnostics log not silent" "$diag"
}

t44_enum_v2_nmap_failure() {
    local s="$RUN/t44"
    mkdir -p "$s/enum"
    run_expect "t44 nmap failure rc=1" 1 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$s/enum" FAKE_NMAP_FAIL=1 \
            "$MODULES/enumeration.sh" "$TARGET_MS2"
    local st diag
    st="$(ls -1dt "$s/enum/${TARGET_MS2}_"*.status.txt 2>/dev/null | head -n1)"
    assert_file "t44 status file written" "$st"
    assert_contains "t44 status error (honest)" "status=error" "$st"
    diag="$(ls -1dt "$s/enum/${TARGET_MS2}_"*.diagnostics.log 2>/dev/null | head -n1)"
    assert_file "t44 diagnostics log not silent" "$diag"
    assert_contains "t44 nmap exit recorded" "exited code 1" "$diag"
}

t45_enum_v2_invalid_target() {
    run_expect "t45 invalid target rc=1" 1 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            "$MODULES/enumeration.sh" "-oX"
}

t46_enum_v2_missing_nmap() {
    local s="$RUN/t46"
    mkdir -p "$s/bin" "$s/enum"
    # A tool binder without nmap (coreutils symlinked only).
    local tool
    for tool in bash env date dirname echo mkdir grep sed awk python3 timeout basename wc cut tail tr head; do
        if command -v "$tool" >/dev/null 2>&1; then
            ln -sf "$(command -v "$tool")" "$s/bin/$tool"
        fi
    done
    run_expect "t46 missing nmap rc=1" 1 \
        env PATH="$s/bin" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$s/enum" \
            "$MODULES/enumeration.sh" "$TARGET_MS2"
    local diag
    diag="$(ls -1dt "$s/enum/${TARGET_MS2}_"*.diagnostics.log 2>/dev/null | head -n1)"
    assert_file "t46 diagnostics log written" "$diag"
    assert_contains "t46 nmap missing noted" "nmap is not installed" "$diag"
}

t47_enum_v2_port_modes() {
    local s="$RUN/t47"
    mkdir -p "$s/enum"
    local log_d="$s/nmap_default.log" log_a="$s/nmap_all.log" log_c="$s/nmap_custom.log"
    rm -f "$log_d" "$log_a" "$log_c"

    run_expect "t47 default mode top-100 rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$s/enum" FAKE_NMAP_UP=1 FAKE_NMAP_LOG="$log_d" \
            "$MODULES/enumeration.sh" "$TARGET_MS2"
    assert_contains "t47 stage1 uses --top-ports 100" "--top-ports 100" "$log_d"
    ( grep -q -- "--script=default" "$log_d" && grep -q -- "-p 21" "$log_d" ) && {
        note "t47 stage2 targeted only discovered ports"
        pass
    } || {
        fail "stage2 not targeted at discovered ports" "t47 stage2"
    }

    run_expect "t47 all-ports mode rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$s/enum" ENUM_PORT_MODE=all FAKE_NMAP_UP=1 FAKE_NMAP_LOG="$log_a" \
            "$MODULES/enumeration.sh" "$TARGET_MS2"
    note "t47 all mode stage1 = -p- (not top-ports)"
    if ( grep -q -- "-p-" "$log_a" && ! grep -q -- "--top-ports" "$log_a" ); then
        pass
    else
        fail "all mode did not use -p-" "t47 all"
    fi

    run_expect "t47 custom NMAP_PORTS honored rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$s/enum" NMAP_PORTS="-p 22-1024" FAKE_NMAP_UP=1 \
            FAKE_NMAP_LOG="$log_c" \
            "$MODULES/enumeration.sh" "$TARGET_MS2"
    assert_contains "t47 custom mode uses -p 22-1024" "-p 22-1024" "$log_c"
}

t48_enum_v2_scripts_safety() {
    local s="$RUN/t48"
    mkdir -p "$s/enum"
    local log="$s/nmap_argv.log"
    rm -f "$log"

    run_expect "t48 default script=default rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$s/enum" FAKE_NMAP_UP=1 FAKE_NMAP_LOG="$log" \
            "$MODULES/enumeration.sh" "$TARGET_MS2"
    note "t48 default NSE = default (no vuln by default)"
    if ( grep -q -- "--script=default" "$log" && ! grep -q -- "--script=.*vuln" "$log" ); then
        pass
    else
        fail "default NSE scripts not safe" "t48 default"
    fi

    run_expect "t48 opt-in NMAP_SCRIPTS=vuln honored rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$s/enum" NMAP_SCRIPTS="vuln" FAKE_NMAP_UP=1 \
            FAKE_NMAP_LOG="$log" \
            "$MODULES/enumeration.sh" "$TARGET_MS2"
    assert_contains "t48 explicit vuln allowed (opt-in)" "--script=vuln" "$log"
}

t49_enum_full_scan_safety() {
    local s="$RUN/t49"
    mkdir -p "$s"
    local log="$s/nmap_argv.log"
    # scan --full with an EXPRESSLY DENIED exploitation approval. Sploit still
    # available on disk via the fakes; without human approval nothing may run.
    run_expect "t49 full scan denied exploit rc=5" 5 \
        ux "$s" env FAKE_NMAP_LOG="$log" timeout 160 \
            bash -c 'printf "1\nn\n" | "$0" scan 203.0.113.7 --full' "$ROOT/scanner.sh"

    local aid st
    aid="$(ls -1dt "$s/assessments"/assessment_* 2>/dev/null | head -n1 | xargs basename)"
    st="$s/assessments/$aid/manifest.json"
    # Manifest records the cancelled phase honestly; never a fabricated session.
    manifest_status "t49 manifest status failed (not completed)" "$st" failed
    manifest_no_phase "t49 exploitation NOT completed" "$st" exploitation
    note "t49 denial left no exploitation session artifacts"
    if [[ -z "$(ls -A "$s/assessments/$aid/exploitation" 2>/dev/null)" ]]; then
        pass
    else
        fail "exploitation artifacts created despite denial" "t49 autoexploit"
    fi
    local r
    r="$(ls -1dt "$s/assessments/$aid/report/"*_*.md 2>/dev/null | head -n1)"
    assert_file "t49 honest report still written" "$r"
    assert_contains "t49 report says exploitation not performed" "not performed" "$r"
    note "t49 full scan default NSE = default (no vuln)"
    if ( grep -q -- "--script=default" "$log" && ! grep -q -- "--script=.*vuln" "$log" ); then
        pass
    else
        fail "full scan invoked unsafe NSE by default" "t49 nse"
    fi
}

# ------------------------------------------------------------------
# main / collection
# ------------------------------------------------------------------

cd "$ROOT" || exit 1

echo "=================================================="
echo " security-assessment test suite"
echo " root:   $ROOT"
echo " fakes:  $FAKES"
echo " config: $CONFIG_FILE"
echo " runs:   $RUN"
echo "=================================================="
echo

t01_syntax
t02_executable
t03_safe_name
t04_invalid_targets
t05_searchsploit_missing
t06_msfconsole_missing
t07_corrupt_xml
t08_no_xml
t09_clean_target
t10_vulnerability
t11_correlation
t12_exploit_denied
t13_exploit_no_session
t14_exploit_session
t15_evidence_session
t16_evidence_no_session
t17_report_full
t18_report_partial
t19_report_no_data
t20_garbage_output
t21_discovery_metadata
t26_scanner_usage
t28_scanner_exploit_chain
t29_scanner_report

t30_ux_helpers
t31_single_phase_exploit
t32_single_phase_enumeration
t33_menu_single_phase
t34_full_pipeline_approved
t35_full_pipeline_declined
t36_scan_full_approved
t37_scan_quick_resume
t38_status
t39_preflight
t40_corrupt_manifest

t41_enum_v2_normal
t42_enum_v2_no_open
t43_enum_v2_malformed_xml
t44_enum_v2_nmap_failure
t45_enum_v2_invalid_target
t46_enum_v2_missing_nmap
t47_enum_v2_port_modes
t48_enum_v2_scripts_safety
t49_enum_full_scan_safety

if [[ "$RUN_NETWORK" == 1 ]]; then
    echo
    echo "[--network] running live localhost enumeration checks..."
    t22_unreachable
    t23_no_open_ports
    t24_open_ports
    t27_scanner_all_unreachable
fi

t25_no_clobber

echo
echo "=================================================="
echo " RESULTS: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
if (( FAIL > 0 )); then
    echo " Failed tests:"
    i=0
    for item in "${FAILED[@]}"; do
        printf '   %d) %s\n' "$i" "$item"
        i=$((i + 1))
    done | sort -n
fi
echo " Run log dir: $RUN"
echo "=================================================="

# cleanup everything we created (unless --keep) and drop the test config
if [[ "$KEEP" != 1 ]]; then
    rm -rf "$RUN" "$ROOT/reports/${TARGET_MS2}_"* "$ROOT/reports/${TARGET_LOOP}_"*
    rm -rf "$OUT/vulnerabilities/${TARGET_MS2}_"* "$OUT/vulnerabilities/${TARGET_CLEAN}_"*
    rm -rf "$OUT/exploitation/${TARGET_MS2}_"* "$OUT/evidence/${TARGET_MS2}_"*
    rm -rf "$OUT/enumeration/${TARGET_MS2}_"* "$OUT/enumeration/${TARGET_LOOP}_"*
    rm -rf "$OUT/enumeration/203.0.113.99_"* "$OUT/nmap/${TARGET_MS2}_"* "$OUT/nmap/203.0.113.99_"*
fi

if (( FAIL > 0 )); then
    exit 1
fi
echo "ALL TESTS PASSED"
exit 0