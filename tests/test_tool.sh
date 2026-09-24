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

# assert_tsv_field <desc> <tsv> <keycol> <key> <col> <want>
assert_tsv_field() {
    local desc="$1" file="$2" keycol="$3" key="$4" col="$5" want="$6"
    note "$desc"
    if awk -F'\t' -v kc="$keycol" -v kw="$key" -v c="$col" -v w="$want" \
        'NR>1 && ($kc==kw) && ($c==w) {hit=1} END {exit hit?0:1}' "$file"; then
        pass
    else
        fail "row[$keycol=$key col=$col] != '$want' ($file)" "$desc"
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

t78_quick_scan_next_step() {
    local s="$RUN/t78"
    mkdir -p "$s"
    local log="$s/quick.log" rc aid m
    ux "$s" timeout 90 "$ROOT/scanner.sh" scan "$TARGET_MS2" --quick >"$log" 2>&1; rc=$?
    note "t78 quick scan rc=0"
    if [[ "$rc" == 0 ]]; then pass; else fail "quick rc=$rc" "t78 rc"; fi
    assert_contains "t78 next-step hint shown" "Continue later with:" "$log"
    assert_contains "t78 hint names resume" "resume" "$log"
    assert_not_contains "t78 non-interactive never prompts" "Start Vulnerability Research now" "$log"
    aid="$(ls -1dt "$s/assessments"/assessment_* 2>/dev/null | head -n1 | xargs basename)"
    [[ -n "$aid" ]] && m="$s/assessments/$aid/manifest.json"
    if [[ -n "$aid" && -n "$m" ]]; then
        manifest_status "t78 quick status completed" "$m" completed
        note "t78 quick never auto-runs vulnerability research"
        if [[ -z "$(ls -1 "$s/assessments/$aid/vulnerabilities" 2>/dev/null)" ]]; then pass; else fail "vulnerabilities auto-ran after quick" "t78 autovuln"; fi
    else
        fail "no assessment created by quick scan" "t78 assessment"
    fi
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
# 10. Regressions: enum artifact selection + searchsploit flag compat
# ------------------------------------------------------------------

# Invoke a lib/common.sh helper in a clean subshell (harness is bash).
common_fn() {
    local fn="$1"; shift
    bash -c 'source "$1"; shift; "$@"' _ "$ROOT/lib/common.sh" "$fn" "$@"
}

t50_enum_artifact_both() {
    local s="$RUN/t50"
    mkdir -p "$s/enum"
    run_expect "t50 enumeration produces both XML families rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$s/enum" FAKE_NMAP_UP=1 \
            "$MODULES/enumeration.sh" "$TARGET_MS2"
    local ports stage2 sel txtsel
    ports="$(ls -1 "$s/enum/${TARGET_MS2}_"*.ports.xml 2>/dev/null | head -n1)"
    stage2="$(ls -1t "$s/enum/${TARGET_MS2}_"*.xml 2>/dev/null | grep -v '\.ports\.xml$' | head -n1)"
    assert_file "t50 stage-1 ports XML exists" "$ports"
    assert_file "t50 stage-2 service XML exists" "$stage2"
    sel="$(common_fn sat_enum_service_xml "$s/enum" "$TARGET_MS2")"
    note "t50 selects stage-2 XML (not stage-1 ports XML)"
    if [[ "$sel" == "$stage2" && "$sel" != "$ports" ]]; then pass; else fail "selected '$sel' (wanted '$stage2')" "t50 xml"; fi
    txtsel="$(common_fn sat_enum_service_txt "$s/enum" "$TARGET_MS2")"
    note "t50 selects stage-2 txt sibling"
    if [[ "$txtsel" == "${stage2%.xml}.txt" ]]; then pass; else fail "selected '$txtsel'" "t50 txt"; fi
}

t51_enum_artifact_stage1_only() {
    local s="$RUN/t51"
    mkdir -p "$s/enum"
    : > "$s/enum/${TARGET_MS2}_20990101_000000000000000.ports.xml"
    cat > "$s/enum/${TARGET_MS2}_20990101_000000000000000.status.txt" <<EOF
status=partial
target=$TARGET_MS2
timestamp=20990101_000000000000000
ports_xml=${TARGET_MS2}_20990101_000000000000000.ports.xml
EOF
    local sel txtsel
    sel="$(common_fn sat_enum_service_xml "$s/enum" "$TARGET_MS2")"
    note "t51 stage-1-only run yields no stage-2 XML"
    if [[ -z "$sel" ]]; then pass; else fail "unexpected selection '$sel'" "t51 xml"; fi
    txtsel="$(common_fn sat_enum_service_txt "$s/enum" "$TARGET_MS2")"
    note "t51 stage-1-only run yields no stage-2 txt"
    if [[ -z "$txtsel" ]]; then pass; else fail "unexpected selection '$txtsel'" "t51 txt"; fi
}

t52_enum_artifact_partial_missing() {
    local s="$RUN/t52"
    mkdir -p "$s/enum"
    : > "$s/enum/${TARGET_MS2}_20990101_000000000000000.ports.xml"
    cat > "$s/enum/${TARGET_MS2}_20990101_000000000000000.status.txt" <<EOF
status=partial
timestamp=20990101_000000000000000
ports_xml=${TARGET_MS2}_20990101_000000000000000.ports.xml
enumeration_xml=${TARGET_MS2}_20990101_000000000000000.xml
enumeration_txt=${TARGET_MS2}_20990101_000000000000000.txt
EOF
    local sel
    sel="$(common_fn sat_enum_service_xml "$s/enum" "$TARGET_MS2")"
    note "t52 status pointing at a missing stage-2 XML is not selected"
    if [[ -z "$sel" ]]; then pass; else fail "unexpected selection '$sel'" "t52 xml"; fi
}

t53_enum_artifact_multiple_historical() {
    local s="$RUN/t53"
    mkdir -p "$s/enum"
    local old="${TARGET_MS2}_20200101_000000000000000"
    local new="${TARGET_MS2}_20200102_000000000000000"
    printf '<?xml version="1.0"?>\n<nmaprun><host><address addr="%s" addrtype="ipv4"/></host></nmaprun>\n' "$TARGET_MS2" > "$s/enum/$old.xml"
    printf '<?xml version="1.0"?>\n<nmaprun><host><address addr="%s" addrtype="ipv4"/></host></nmaprun>\n' "$TARGET_MS2" > "$s/enum/$new.xml"
    : > "$s/enum/$old.ports.xml"
    : > "$s/enum/$new.ports.xml"
    printf 'stage2 old\n' > "$s/enum/$old.txt"
    printf 'stage2 new\n' > "$s/enum/$new.txt"
    cat > "$s/enum/$old.status.txt" <<EOF
status=completed
timestamp=20200101_000000000000000
enumeration_xml=$old.xml
enumeration_txt=$old.txt
ports_xml=$old.ports.xml
EOF
    cat > "$s/enum/$new.status.txt" <<EOF
status=completed
timestamp=20200102_000000000000000
enumeration_xml=$new.xml
enumeration_txt=$new.txt
ports_xml=$new.ports.xml
EOF
    # mtimes deliberately reversed: recorded timestamps must win, not mtime/glob order.
    touch -d '2020-01-01 00:00:00' "$s/enum/$new.xml" "$s/enum/$new.txt" "$s/enum/$new.status.txt" "$s/enum/$new.ports.xml"
    touch -d '2021-01-01 00:00:00' "$s/enum/$old.xml" "$s/enum/$old.txt" "$s/enum/$old.status.txt" "$s/enum/$old.ports.xml"
    local sel txtsel
    sel="$(common_fn sat_enum_service_xml "$s/enum" "$TARGET_MS2")"
    note "t53 newest recorded run wins (not mtime/lexical)"
    if [[ "$sel" == "$s/enum/$new.xml" ]]; then pass; else fail "selected '$sel'" "t53 xml"; fi
    txtsel="$(common_fn sat_enum_service_txt "$s/enum" "$TARGET_MS2")"
    note "t53 newest recorded stage-2 txt wins"
    if [[ "$txtsel" == "$s/enum/$new.txt" ]]; then pass; else fail "selected '$txtsel'" "t53 txt"; fi
}

t54_enum_artifact_legacy_no_status() {
    local s="$RUN/t54"
    mkdir -p "$s/enum"
    local old="${TARGET_MS2}_20200101_000000000000000"
    local new="${TARGET_MS2}_20200102_000000000000000"
    : > "$s/enum/$old.xml"
    : > "$s/enum/$new.ports.xml"
    touch -d '2020-01-01 00:00:00' "$s/enum/$old.xml"
    touch -d '2020-01-02 00:00:00' "$s/enum/$new.ports.xml"
    local sel
    sel="$(common_fn sat_enum_service_xml "$s/enum" "$TARGET_MS2")"
    note "t54 legacy status-less fallback ignores stage-1 ports XML"
    if [[ "$sel" == "$s/enum/$old.xml" ]]; then pass; else fail "selected '$sel'" "t54 xml"; fi
}

t55_vuln_autoselect_stage2() {
    local s="$RUN/t55"
    mkdir -p "$s/enum" "$s/vuln"
    run_expect "t55 enumeration fixture rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_ENUM="$s/enum" FAKE_NMAP_UP=1 \
            "$MODULES/enumeration.sh" "$TARGET_MS2"
    # No explicit XML argument: the module must select the stage-2 file itself.
    run_expect "t55 vuln auto-selects stage-2 XML rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            FAKE_SEARCHSPLOIT_FLAG_MODE=modern \
            OUTPUT_ENUM="$s/enum" OUTPUT_VULN="$s/vuln" \
            "$MODULES/vulnerability.sh" "$TARGET_MS2"
    local d
    d="$(latest_dir "$s/vuln/${TARGET_MS2}_")"
    assert_contains "t55 candidate vsftpd found" "17491" "$d/exploitdb_candidates.tsv"
    note "t55 vulnerability phase did not use a stage-1 ports XML"
    if grep -q 'enumeration_xml=.*\.ports\.xml' "$d/status.txt"; then
        fail "vulnerability phase used stage-1 ports XML" "t55 xml"
    else
        pass
    fi
}

t56_report_uses_stage2_text() {
    local s="$RUN/t56" safe="$TARGET_MS2"
    local base="${safe}_20990101_000000000000000"
    mkdir -p "$s/enum" "$s/reports" "$s/nmap" "$s/vuln" "$s/exploit" "$s/evidence"
    # Stage-1 text carries a decoy version; stage-2 carries the real one.
    printf '21/tcp open  ftp     vsftpd 9.9.9\n' > "$s/enum/$base.ports.nmap.txt"
    printf '21/tcp open  ftp     vsftpd 9.9.9\n' > "$s/enum/$base.ports.txt"
    printf '21/tcp open  ftp     vsftpd 2.3.4\n' > "$s/enum/$base.txt"
    printf '<?xml version="1.0"?>\n<nmaprun><host><address addr="%s" addrtype="ipv4"/><hostnames/><ports/></host></nmaprun>\n' "$safe" > "$s/enum/$base.xml"
    : > "$s/enum/$base.ports.xml"
    cat > "$s/enum/$base.status.txt" <<EOF
status=completed
target=$safe
timestamp=20990101_000000000000000
ports_xml=$base.ports.xml
enumeration_xml=$base.xml
enumeration_txt=$base.txt
EOF
    run_expect "t56 report against stage-2 artifacts rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            OUTPUT_NMAP="$s/nmap" OUTPUT_ENUM="$s/enum" OUTPUT_VULN="$s/vuln" \
            OUTPUT_EXPLOIT="$s/exploit" OUTPUT_EVIDENCE="$s/evidence" \
            OUTPUT_REPORTS="$s/reports" \
            "$MODULES/report.sh" "$safe"
    local f
    f="$(ls -1dt "$s/reports/${safe}_"*.md 2>/dev/null | head -n1)"
    assert_file "t56 markdown report written" "$f"
    assert_contains "t56 report uses stage-2 version" "vsftpd 2.3.4" "$f"
    assert_not_contains "t56 report ignores stage-1 decoy version" "9.9.9" "$f"
}

t57_searchsploit_colour_modern() {
    local s="$RUN/t57"
    mkdir -p "$s/vuln"
    run_expect "t57 modern searchsploit (--disable-colour) rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            FAKE_SEARCHSPLOIT_FLAG_MODE=modern OUTPUT_VULN="$s/vuln" \
            "$MODULES/vulnerability.sh" "$TARGET_MS2" "$MS2_XML"
    local d
    d="$(latest_dir "$s/vuln/${TARGET_MS2}_")"
    assert_contains "t57 candidates=3" "candidates=3" "$d/status.txt"
    assert_contains "t57 candidate 17491" "17491" "$d/exploitdb_candidates.tsv"
    assert_contains "t57 candidate 16320" "16320" "$d/exploitdb_candidates.tsv"
    assert_not_contains "t57 no illegal-option dump" "illegal option" "$d/searchsploit_raw/combined_raw.txt"
}

t58_searchsploit_colour_legacy() {
    local s="$RUN/t58"
    mkdir -p "$s/vuln"
    run_expect "t58 legacy searchsploit (--colour=0) rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            FAKE_SEARCHSPLOIT_FLAG_MODE=legacy OUTPUT_VULN="$s/vuln" \
            "$MODULES/vulnerability.sh" "$TARGET_MS2" "$MS2_XML"
    local d
    d="$(latest_dir "$s/vuln/${TARGET_MS2}_")"
    assert_contains "t58 candidates=3" "candidates=3" "$d/status.txt"
    assert_contains "t58 candidate 17491" "17491" "$d/exploitdb_candidates.tsv"
    assert_not_contains "t58 no illegal-option dump" "illegal option" "$d/searchsploit_raw/combined_raw.txt"
}

t59_searchsploit_colour_plain() {
    local s="$RUN/t59"
    mkdir -p "$s/vuln"
    run_expect "t59 searchsploit with no colour option rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            FAKE_SEARCHSPLOIT_FLAG_MODE=plain OUTPUT_VULN="$s/vuln" \
            "$MODULES/vulnerability.sh" "$TARGET_MS2" "$MS2_XML"
    local d
    d="$(latest_dir "$s/vuln/${TARGET_MS2}_")"
    assert_contains "t59 candidates=3" "candidates=3" "$d/status.txt"
    assert_not_contains "t59 no illegal-option dump" "illegal option" "$d/searchsploit_raw/combined_raw.txt"
}

t60_searchsploit_failure_not_fabricated() {
    local s="$RUN/t60"
    mkdir -p "$s/vuln"
    run_expect "t60 failing searchsploit rc=0 (honest, no fabrication)" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            FAKE_SEARCHSPLOIT_USAGE_ERR=1 OUTPUT_VULN="$s/vuln" \
            "$MODULES/vulnerability.sh" "$TARGET_MS2" "$MS2_XML"
    local d
    d="$(latest_dir "$s/vuln/${TARGET_MS2}_")"
    assert_contains "t60 status completed (honest)" "status=completed" "$d/status.txt"
    assert_contains "t60 candidates=0" "candidates=0" "$d/status.txt"
    assert_file "t60 candidates file header only" "$d/exploitdb_candidates.tsv"
    assert_count "t60 no fabricated candidate rows" "$d/exploitdb_candidates.tsv" 0
    assert_contains "t60 failure preserved in raw evidence" "illegal option" "$d/searchsploit_raw/combined_raw.txt"
}

# ------------------------------------------------------------------
# 11. Correlation accuracy (live-test findings) & exploitation flow
# ------------------------------------------------------------------

# _write_corr <dir> <target>  - synthetic Phase 3+4 tree: vsftpd(high, mapped),
#                               samba(medium, mapped), Apache Jserv(medium, unmapped)
_write_corr() {
    local d="$1" t="$2"
    mkdir -p "$d"
    printf 'status=completed\n' > "$d/status.txt"
    printf 'index\tip\tport\tprotocol\tservice\tproduct\tversion\textrainfo\n' > "$d/services.tsv"
    printf '1\t%s\t21\ttcp\tftp\tvsftpd\t2.3.4\t\n' "$t" >> "$d/services.tsv"
    printf '2\t%s\t139\ttcp\tnetbios-ssn\tSamba smbd\t3.0.20-Debian\t\n' "$t" >> "$d/services.tsv"
    printf '3\t%s\t8009\ttcp\tajp13\tApache Jserv\t1.2\t\n' "$t" >> "$d/services.tsv"
    printf 'service_index\tport\tprotocol\tservice\tproduct\tversion\tquery\tedb_id\ttitle\tpath\tplatform\ttype\tcve\n' > "$d/exploitdb_candidates.tsv"
    printf '1\t\t\t\t\t\t\t17491\tvsftpd 2.3.4 - Backdoor Command Execution\texploits/linux/remote/17491.rb\tlinux\tremote\t\n' >> "$d/exploitdb_candidates.tsv"
    printf '2\t\t\t\t\t\t\t16320\tSamba 3.0.20 < 3.0.25rc3 - Username map script Command Execution\texploits/multi/samba/16320.rb\tlinux\tremote\t\n' >> "$d/exploitdb_candidates.tsv"
    printf '3\t\t\t\t\t\t\t30004\tApache Jserv Remote Buffer Overflow\texploits/multi/http/30004.rb\tlinux\tremote\t\n' >> "$d/exploitdb_candidates.tsv"
    {
        echo "target	port	protocol	service	product	detected_version	exploit_title	edb_id	exploit_path	cve	platform	type	search_query	confidence	severity	severity_source	match_reason	match_type	risk_category	evidence_confidence	version_evidence"
        printf '%s\t21\ttcp\tftp\tvsftpd\t2.3.4\tvsftpd 2.3.4 - Backdoor Command Execution\t17491\texploits/linux/remote/17491.rb\t\tlinux\tremote\tvsftpd 2.3.4\thigh\thigh\ttool-assessment\texact\tEXACT_VERSION_MATCH\thigh\thigh\texact\n' "$t"
        printf '%s\t139\ttcp\tnetbios-ssn\tSamba smbd\t3.0.20-Debian\tSamba 3.0.20 < 3.0.25rc3 - Username map script Command Execution\t16320\texploits/multi/samba/16320.rb\t\tlinux\tremote\tsamba 3.0.20\tmedium\tmedium\ttool-assessment\trange\tVERSION_RANGE_MATCH\tmedium\tmedium\trange\n' "$t"
        printf '%s\t8009\ttcp\tajp13\tApache Jserv\t1.2\tApache Jserv Remote Buffer Overflow\t30004\texploits/multi/http/30004.rb\t\tlinux\tremote\tapache jserv\tmedium\tmedium\ttool-assessment\tstrong\tSTRONG_PRODUCT_SERVICE_MATCH\tmedium\tmedium\tstrong\n' "$t"
    } > "$d/correlated_findings.tsv"
}

t61_corr_version_semantics() {
    local s="$RUN/t61"
    local src="$s/src"
    local t="203.0.113.66"
    mkdir -p "$s/vuln" "$src"
    printf 'index\tip\tport\tprotocol\tservice\tproduct\tversion\textrainfo\n' > "$src/services.tsv"
    printf '1\t%s\t139\ttcp\tnetbios-ssn\tSamba smbd\t3.X - 4.X\t\n' "$t" >> "$src/services.tsv"
    printf '2\t%s\t139\ttcp\tnetbios-ssn\tSamba smbd\t3.0.20-Debian\t\n' "$t" >> "$src/services.tsv"
    printf '3\t%s\t139\ttcp\tnetbios-ssn\tSamba smbd\t3.0.20-Debian\t\n' "$t" >> "$src/services.tsv"
    printf 'service_index\tport\tprotocol\tservice\tproduct\tversion\tquery\tedb_id\ttitle\tpath\tplatform\ttype\tcve\n' > "$src/exploitdb_candidates.tsv"
    printf '1\t\t\t\t\t\t\t22470\tSamba 2.2.x - call_trans2open Remote Buffer Overflow\texploits/multiple/remote/22470.rb\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '2\t\t\t\t\t\t\t16320\tSamba 3.0.20 < 3.0.25rc3 - Username map script Command Execution\texploits/multi/samba/16320.rb\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '3\t\t\t\t\t\t\t19999\tSamba 3.5.0 - Remote Code Execution\texploits/multi/samba/19999.rb\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    run_expect "t61 correlation version semantics rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" OUTPUT_VULN="$s/vuln" \
        "$MODULES/correlation.sh" "$t" "$src"
    local d f
    d="$(latest_dir "$s/vuln/${t}_")"
    f="$d/correlated_findings.tsv"
    assert_file "t61 correlated tsv" "$f"
    # Samba 2.2.x exploit against a detected '3.X - 4.X' host must NOT be
    # flagged as an exact/high finding (live-test regression).
    assert_tsv_field "t61 2.2.x vs generic 3.X-4.X -> version-unknown" "$f" 8 22470 18 VERSION_UNKNOWN
    assert_tsv_field "t61 2.2.x low risk" "$f" 8 22470 20 low
    assert_tsv_field "t61 2.2.x low severity" "$f" 8 22470 15 low
    assert_tsv_field "t61 3.0.20 falls in 3.0.20..3.0.25 -> range" "$f" 8 16320 18 VERSION_RANGE_MATCH
    assert_tsv_field "t61 3.0.20 range medium" "$f" 8 16320 20 medium
    assert_tsv_field "t61 3.5.0 conflicts with 3.0.20" "$f" 8 19999 18 VERSION_CONFLICT
    assert_tsv_field "t61 conflict low/low" "$f" 8 19999 20 low
    assert_contains "t61 status findings_high=0" "findings_high=0" "$d/status.txt"
    assert_contains "t61 status findings_medium=1" "findings_medium=1" "$d/status.txt"
}

t62_corr_product_specificity() {
    local s="$RUN/t62"
    local src="$s/src"
    local t="203.0.113.67"
    mkdir -p "$s/vuln" "$src"
    printf 'index\tip\tport\tprotocol\tservice\tproduct\tversion\textrainfo\n' > "$src/services.tsv"
    for i in 1 2 3 4 5; do
        printf '%s\t%s\t8009\ttcp\tajp13\tApache Jserv\t1.2\t\n' "$i" "$t" >> "$src/services.tsv"
    done
    printf 'service_index\tport\tprotocol\tservice\tproduct\tversion\tquery\tedb_id\ttitle\tpath\tplatform\ttype\tcve\n' > "$src/exploitdb_candidates.tsv"
    printf '1\t\t\t\t\t\t\t30001\tApache Tomcat - Remote Code Execution\texploits/multi/http/30001.rb\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '2\t\t\t\t\t\t\t30002\tApache Struts - Command Execution\texploits/multi/http/30002.rb\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '3\t\t\t\t\t\t\t30003\tApache Spark - Unauthenticated Code Execution\texploits/multi/http/30003.rb\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '4\t\t\t\t\t\t\t30005\tApache Xerces - Denial of Service\texploits/multi/http/30005.rb\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '5\t\t\t\t\t\t\t30004\tApache Jserv - Remote Buffer Overflow\texploits/multi/http/30004.rb\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    run_expect "t62 correlation product specificity rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" OUTPUT_VULN="$s/vuln" \
        "$MODULES/correlation.sh" "$t" "$src"
    local d f
    d="$(latest_dir "$s/vuln/${t}_")"
    f="$d/correlated_findings.tsv"
    assert_file "t62 correlated tsv" "$f"
    local edb
    for edb in 30001 30002 30003 30005; do
        assert_tsv_field "t62 EDB-$edb shares only vendor word" "$f" 8 "$edb" 18 VENDOR_ONLY_MATCH
        assert_tsv_field "t62 EDB-$edb low/low" "$f" 8 "$edb" 20 low
    done
    assert_tsv_field "t62 stack-specific component promoted to strong" "$f" 8 30004 18 STRONG_PRODUCT_SERVICE_MATCH
    assert_tsv_field "t62 jserv medium evidence" "$f" 8 30004 20 medium
}

t67_corr_wildcard_versions() {
    # Bug #2 regression: wildcarded / partial / suffixed / malformed candidate
    # versions must never crash vtuple() with a ValueError, must never be
    # promoted to a high-confidence version match, and exact/range/conflict
    # version behaviour must be preserved. 'Samba smbd' is a two-token product
    # whose specific component ('smbd') is absent from titles, so the
    # service-specific upgrade does not mask the version classification.
    local s="$RUN/t67"
    local src="$s/src"
    local t="203.0.113.69"
    mkdir -p "$s/vuln" "$src"
    printf 'index\tip\tport\tprotocol\tservice\tproduct\tversion\textrainfo\n' > "$src/services.tsv"
    printf '1\t%s\t139\ttcp\tnetbios-ssn\tSamba smbd\t3.0.20-Debian\t\n' "$t" >> "$src/services.tsv"
    printf '2\t%s\t21\ttcp\tftp\tvsftpd\t2.3.4\t\n' "$t" >> "$src/services.tsv"
    printf 'service_index\tport\tprotocol\tservice\tproduct\tversion\tquery\tedb_id\ttitle\tpath\tplatform\ttype\tcve\n' > "$src/exploitdb_candidates.tsv"
    printf '1\t\t\t\t\t\t\t70001\tSamba 2.x - Remote Denial of Service\texploits/linux/remote/70001.c\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '1\t\t\t\t\t\t\t70002\tSamba 2.2.x - Remote Denial of Service\texploits/linux/remote/70002.c\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '1\t\t\t\t\t\t\t70003\tSamba 3.X - Remote Buffer Overflow\texploits/linux/remote/70003.rb\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '1\t\t\t\t\t\t\t70004\tSamba 1.2x - Remote Chroot Breakout\texploits/linux/remote/70004.c\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '1\t\t\t\t\t\t\t70005\tSamba 3.xx - Broken Version Denial of Service\texploits/linux/remote/70005.c\tlinux\tdos\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '1\t\t\t\t\t\t\t70006\tSamba version not stated - Authentication Bypass\texploits/linux/remote/70006.rb\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '1\t\t\t\t\t\t\t16320\tSamba 3.0.20 < 3.0.25rc3 - Username map script Command Execution\texploits/multi/samba/16320.rb\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '1\t\t\t\t\t\t\t19999\tSamba 3.5.0 - Remote Code Execution\texploits/multi/samba/19999.rb\tlinux\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    printf '2\t\t\t\t\t\t\t17491\tvsftpd 2.3.4 - Backdoor Command Execution\texploits/unix/remote/17491.rb\tunix\tremote\t\n' >> "$src/exploitdb_candidates.tsv"
    run_expect "t67 correlation wildcard versions rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" OUTPUT_VULN="$s/vuln" \
        "$MODULES/correlation.sh" "$t" "$src"
    local d f
    d="$(latest_dir "$s/vuln/${t}_")"
    f="$d/correlated_findings.tsv"
    assert_file "t67 correlated tsv" "$f"
    assert_count "t67 all nine candidates kept" "$f" 9
    assert_contains "t67 status findings_high=1 vsftpd exact" "findings_high=1" "$d/status.txt"
    assert_contains "t67 status findings_medium=1 range" "findings_medium=1" "$d/status.txt"
    assert_contains "t67 status findings_low=7" "findings_low=7" "$d/status.txt"

    local edb
    for edb in 70001 70002 70003 70004 70005; do
        assert_tsv_field "t67 EDB-$edb classified version-unknown" "$f" 8 "$edb" 18 VERSION_UNKNOWN
        assert_tsv_field "t67 EDB-$edb low evidence" "$f" 8 "$edb" 20 low
    done
    assert_tsv_field "t67 2.x wildcard not exact" "$f" 8 70001 18 VERSION_UNKNOWN
    assert_tsv_field "t67 2.2.x partial wildcard not exact" "$f" 8 70002 18 VERSION_UNKNOWN
    assert_tsv_field "t67 3.X uppercase wildcard not exact" "$f" 8 70003 18 VERSION_UNKNOWN
    assert_tsv_field "t67 suffixed 1.2x crash token not exact" "$f" 8 70004 18 VERSION_UNKNOWN
    assert_tsv_field "t67 malformed 3.xx not exact" "$f" 8 70005 18 VERSION_UNKNOWN
    assert_tsv_field "t67 no-version candidate low product match" "$f" 8 70006 18 PRODUCT_MATCH_ONLY
    assert_tsv_field "t67 range behaviour preserved" "$f" 8 16320 18 VERSION_RANGE_MATCH
    assert_tsv_field "t67 range medium evidence" "$f" 8 16320 20 medium
    assert_tsv_field "t67 conflict behaviour preserved" "$f" 8 19999 18 VERSION_CONFLICT
    assert_tsv_field "t67 conflict low evidence" "$f" 8 19999 20 low
    assert_tsv_field "t67 exact vsftpd preserved" "$f" 8 17491 18 EXACT_VERSION_MATCH
    assert_tsv_field "t67 exact high evidence" "$f" 8 17491 20 high

    # Malformed / wildcard candidates must not abort the phase: explicit
    # no-traceback check on the live crash token (1.2x).
    LOGNO=$((LOGNO + 1))
    note "t67 no Python traceback on wildcard/malformed versions"
    env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" OUTPUT_VULN="$s/vuln" \
        "$MODULES/correlation.sh" "$t" "$src" >"$RUN/$LOGNO.log" 2>&1
    if ! grep -qE "Traceback|ValueError" "$RUN/$LOGNO.log"; then
        pass
    else
        fail "python traceback appeared" "t67 traceback"
        if [[ "$VERBOSE" == 1 ]]; then sed -n '1,40p' "$RUN/$LOGNO.log" | sed 's/^/    /'; fi
    fi
}

# _write_assessment_enum <root> <aid> <target> <xmlsrc> <stamp>
# Synthetic assessment with enumeration Stage-1 + Stage-2 artifact families
# (mirrors what modules/enumeration.sh writes inside an assessment).
_write_assessment_enum() {
    local root="$1" aid="$2" tgt="$3" xmlsrc="$4" stamp="$5"
    local adir edir base
    adir="$root/$aid"
    edir="$adir/enumeration"
    base="${tgt}_${stamp}"
    mkdir -p "$edir" "$adir"
    python3 - "$adir/manifest.json" "$aid" "$tgt" <<'PY'
import json
import sys
p, aid, tgt = sys.argv[1:4]
json.dump({
    "assessment_id": aid,
    "target": tgt,
    "started_at": "2026-01-01T00:00:00+0000",
    "updated_at": "2026-01-01T00:00:00+0000",
    "status": "in_progress",
    "current_phase": "enumeration",
    "completed_phases": ["discovery", "enumeration"],
    "failed_phases": [],
}, open(p, "w"), indent=2)
PY
    printf '%s\n' '<nmaprun><host><ports></ports></host></nmaprun>' > "$edir/$base.ports.xml"
    printf '# stage1 port scan\n' > "$edir/$base.ports.txt"
    cp "$xmlsrc" "$edir/$base.xml"
    printf '# stage2 service enumeration\n' > "$edir/$base.txt"
    {
        echo "target=$tgt"
        echo "timestamp=${stamp}000000000"
        echo "enumeration_xml=$base.xml"
        echo "enumeration_txt=$base.txt"
    } > "$edir/$base.status.txt"
}

t68_enum_xml_resolution() {
    # Bug #1 regression: a Quick Scan's assessment-scoped enumeration
    # artifacts must be resolvable by the legacy standalone phase commands,
    # in the prescribed order (assessment-scoped -> legacy -> explicit path),
    # never picking a Stage-1 ".ports.xml".
    local s="$RUN/t68"
    local leg="$s/legacy"
    local asse="$s/assessments"
    local vuln="$s/vuln"
    mkdir -p "$leg" "$asse" "$vuln"

    # ---- legacy-only artifact: must resolve rc=0 -------------------------
    local t="203.0.113.90"
    local lbase="${t}_20260101_100000"
    cp "$MS2_XML" "$leg/$lbase.xml"
    printf '# legacy stage2\n' > "$leg/$lbase.txt"
    {
        echo "target=$t"
        echo "timestamp=20260101100000000000"
        echo "enumeration_xml=$lbase.xml"
        echo "enumeration_txt=$lbase.txt"
    } > "$leg/$lbase.status.txt"
    run_expect "t68 legacy-only enumeration XML rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            ASSESSMENTS_ROOT="$asse" OUTPUT_ENUM="$leg" OUTPUT_VULN="$vuln" \
            "$MODULES/vulnerability.sh" "$t"
    local d
    d="$(latest_dir "$vuln/${t}_")"
    assert_contains "t68 legacy artifact selected" "enumeration_xml=$leg/$lbase.xml" "$d/status.txt"

    # ---- assessment-scoped artifact wins over legacy ---------------------
    local ns="assessment_20260101_000000000000001"
    _write_assessment_enum "$asse" "$ns" "$t" "$MS2_XML" "20260101_090000"
    run_expect "t68 assessment XML resolves (rc=0)" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            ASSESSMENTS_ROOT="$asse" OUTPUT_ENUM="$leg" OUTPUT_VULN="$vuln" \
            "$MODULES/vulnerability.sh" "$t"
    d="$(latest_dir "$vuln/${t}_")"
    assert_contains "t68 assessment artifact preferred over legacy" \
        "enumeration_xml=$asse/$ns/enumeration/${t}_20260101_090000.xml" "$d/status.txt"
    assert_contains "t68 services extracted from stage-2 XML" "vsftpd" "$d/services.tsv"

    # ---- newest assessment wins, still never a .ports.xml ----------------
    local ns2="assessment_20260101_000000000000002"
    _write_assessment_enum "$asse" "$ns2" "$t" "$MS2_XML" "20260101_090500"
    run_expect "t68 newest assessment wins (rc=0)" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            ASSESSMENTS_ROOT="$asse" OUTPUT_ENUM="$leg" OUTPUT_VULN="$vuln" \
            "$MODULES/vulnerability.sh" "$t"
    d="$(latest_dir "$vuln/${t}_")"
    assert_contains "t68 newest assessment selected" \
        "enumeration_xml=$asse/$ns2/enumeration/${t}_20260101_090500.xml" "$d/status.txt"
    assert_not_contains "t68 stage-1 .ports.xml never selected" ".ports.xml" "$d/status.txt"

    # ---- explicit XML path always wins ------------------------------------
    local explicit="$leg/${t}_explicit.xml"
    cp "$CLEAN_XML" "$explicit"
    run_expect "t68 explicit XML path rc=0" 0 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            ASSESSMENTS_ROOT="$asse" OUTPUT_ENUM="$leg" OUTPUT_VULN="$vuln" \
            "$MODULES/vulnerability.sh" "$t" "$explicit"
    d="$(latest_dir "$vuln/${t}_")"
    assert_contains "t68 explicit XML path honored" "enumeration_xml=$explicit" "$d/status.txt"

    # ---- only a Stage-1 .ports.xml present -> honest rc=2 ----------------
    local t2="203.0.113.92"
    mkdir -p "$vuln" "$leg/of"
    local l2b="${t2}_20260101_100000"
    printf '%s\n' '<nmaprun><host><ports></ports></host></nmaprun>' > "$leg/$l2b.ports.xml"
    printf '# stage1\n' > "$leg/$l2b.ports.txt"
    run_expect "t68 stage-1-only is not a usable XML rc=2" 2 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            ASSESSMENTS_ROOT="$asse" OUTPUT_ENUM="$leg" OUTPUT_VULN="$vuln" \
            "$MODULES/vulnerability.sh" "$t2"

    # ---- no artifact anywhere -> rc=2 -------------------------------------
    run_expect "t68 no XML anywhere rc=2" 2 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            ASSESSMENTS_ROOT="$asse" OUTPUT_ENUM="$leg" OUTPUT_VULN="$vuln" \
            "$MODULES/vulnerability.sh" "$TARGET_NOART"

    # ---- malformed assessment-scoped XML -> honest rc=1 -------------------
    local t3="203.0.113.93"
    local ns3="assessment_20260101_000000000000003"
    _write_assessment_enum "$asse" "$ns3" "$t3" "$CORRUPT_XML" "20260101_090000"
    run_expect "t68 malformed assessment XML rc=1" 1 \
        env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
            ASSESSMENTS_ROOT="$asse" OUTPUT_ENUM="$leg" OUTPUT_VULN="$vuln" \
            "$MODULES/vulnerability.sh" "$t3"

    # ---- end-to-end: scanner quick scan then legacy vulnerabilities -------
    local em="$RUN/t68e2e"
    mkdir -p "$em"
    local t4="203.0.113.91"
    run_expect "t68 quick scan runs discovery+enumeration rc=0" 0 \
        ux "$em" timeout 90 "$ROOT/scanner.sh" scan "$t4" --quick
    run_expect "t68 legacy vulnerabilities reuses quick-scan XML rc=0" 0 \
        ux "$em" timeout 90 "$ROOT/scanner.sh" "$t4" vulnerabilities
    local vd
    vd="$(latest_dir "$em/vuln/${t4}_")"
    assert_contains "t68 legacy vuln used assessment-scoped XML" \
        "enumeration_xml=$em/assessments/" "$vd/status.txt"
    assert_not_contains "t68 legacy vuln excludes stage-1 artifact" ".ports.xml" "$vd/status.txt"
    assert_contains "t68 quick-scan target services present" "vsftpd" "$vd/services.tsv"
}

# ------------------------------------------------------------------
# Scope CLI regression (documented form, parser intentionally positional).
#   scope create <assessment-id> <targets...> [--name <n>] [--parent <sid>]
# ------------------------------------------------------------------

t79_scope_create_name() {
    local s="$RUN/t79"
    mkdir -p "$s"
    local aid="assessment_t79" dir rc
    ux "$s" timeout 60 "$ROOT/scanner.sh" scope create "$aid" 192.168.1.84 --name lab-scope \
        >"$s/create.log" 2>&1; rc=$?
    note "t79 scope create rc=0"
    if [[ "$rc" == 0 ]]; then pass; else fail "create rc=$rc" "t79 rc"; fi
    dir="$(ls -1dt "$s/assessments/$aid/scopes"/scope_* 2>/dev/null | head -n1)"
    assert_file "t79 scope.json" "$dir/scope.json"
    assert_contains "t79 explicit name preserved" "lab-scope" "$dir/scope.json"
    assert_contains "t79 type ip" '"type": "ip"' "$dir/scope.json"
    assert_contains "t79 target_count 1" '"target_count": 1' "$dir/scope.json"
    assert_contains "t79 target stored" '"192.168.1.84"' "$dir/scope.json"
    assert_contains "t79 status pending" '"status": "pending"' "$dir/scope.json"

    ux "$s" timeout 60 "$ROOT/scanner.sh" scope create "$aid" 192.168.1.85 --name lab2 \
        >"$s/create2.log" 2>&1
    local n
    n="$(ls -1d "$s/assessments/$aid/scopes"/scope_* 2>/dev/null | wc -l)"
    note "t79 create never overwrites an existing scope"
    if [[ "$n" == 2 ]]; then pass; else fail "expected 2 scopes, found $n" "t79 count"; fi
    assert_file "t79 first scope preserved" "$dir/scope.json"
}

t80_scope_create_cidr() {
    local s="$RUN/t80"
    mkdir -p "$s"
    local aid="assessment_t80" dir
    ux "$s" timeout 60 "$ROOT/scanner.sh" scope create "$aid" 192.168.1.0/24 --name lab-scope \
        >"$s/create.log" 2>&1
    dir="$(ls -1dt "$s/assessments/$aid/scopes"/scope_* 2>/dev/null | head -n1)"
    assert_file "t80 scope.json" "$dir/scope.json"
    assert_contains "t80 type cidr" '"type": "cidr"' "$dir/scope.json"
    assert_contains "t80 cidr expanded to 254 hosts" '"target_count": 254' "$dir/scope.json"
    assert_contains "t80 first host included" '"192.168.1.1"' "$dir/scope.json"
    assert_contains "t80 last host included" '"192.168.1.254"' "$dir/scope.json"
    assert_not_contains "t80 network address excluded" '"192.168.1.0"' "$dir/scope.json"
    assert_not_contains "t80 broadcast address excluded" '"192.168.1.255"' "$dir/scope.json"
}

t81_scope_create_dedupe_hostname() {
    local s="$RUN/t81"
    mkdir -p "$s"
    local aid="assessment_t81" dir
    ux "$s" timeout 60 "$ROOT/scanner.sh" scope create "$aid" \
        192.168.1.84 192.168.1.85 192.168.1.84 host.example.com --name lab-scope \
        >"$s/create.log" 2>&1
    dir="$(ls -1dt "$s/assessments/$aid/scopes"/scope_* 2>/dev/null | head -n1)"
    assert_file "t81 scope.json" "$dir/scope.json"
    assert_contains "t81 type hostname" '"type": "hostname"' "$dir/scope.json"
    assert_contains "t81 dedupe to 3 targets" '"target_count": 3' "$dir/scope.json"
    assert_contains "t81 hostname lowercased" '"host.example.com"' "$dir/scope.json"
    local dup n
    dup="$(grep -cF '"192.168.1.84"' "$dir/scope.json")"
    note "t81 duplicate target removed"
    if [[ "$dup" == 1 ]]; then pass; else fail "duplicate not removed (found $dup)" "t81 dedupe"; fi
    n="$(grep -c '^    "' "$dir/scope.json")"
    note "t81 target list length matches count"
    if [[ "$n" == 3 ]]; then pass; else fail "listed $n targets" "t81 list"; fi
}

t82_scope_list_show_status() {
    local s="$RUN/t82"
    mkdir -p "$s"
    local aid="assessment_t82" dir sid
    ux "$s" timeout 60 "$ROOT/scanner.sh" scope create "$aid" 192.168.1.84 192.168.1.85 --name lab-scope \
        >"$s/create.log" 2>&1
    dir="$(ls -1dt "$s/assessments/$aid/scopes"/scope_* 2>/dev/null | head -n1)"
    sid="$(basename "$dir")"

    ux "$s" timeout 60 "$ROOT/scanner.sh" scope list "$aid" >"$s/list.log" 2>&1
    assert_contains "t82 list shows scope id" "$sid" "$s/list.log"
    assert_contains "t82 list shows type" "ip" "$s/list.log"

    ux "$s" timeout 60 "$ROOT/scanner.sh" scope show "$sid" >"$s/show.log" 2>&1
    assert_contains "t82 show name" "lab-scope" "$s/show.log"
    assert_contains "t82 show scope_id" "$sid" "$s/show.log"

    ux "$s" timeout 60 "$ROOT/scanner.sh" scope status "$sid" >"$s/status.log" 2>&1
    assert_contains "t82 status heading" "Scope status: $sid" "$s/status.log"
    assert_contains "t82 status pending" "scope status: pending" "$s/status.log"
    assert_contains "t82 status totals" "targets:" "$s/status.log"
}

# ------------------------------------------------------------------
# Assessment reuse / immutability: scans always create distinct
# assessments; resuming one never touches another; scope create on an
# existing assessment is idempotent and non-destructive.
# ------------------------------------------------------------------

t83_assessment_reuse_immutability() {
    local s="$RUN/t83"
    mkdir -p "$s"
    local from="$s/assessments"

    ux "$s" timeout 90 "$ROOT/scanner.sh" scan "$TARGET_MS2" --quick >"$s/scan1.log" 2>&1
    local a1 snap1 a2 aid1 n
    a1="$(ls -1dt "$from"/assessment_* 2>/dev/null | head -n1)"
    snap1="$(find "$a1" -type f 2>/dev/null | sort | sed 's#.*/##'; cat "$a1/manifest.json")"
    ux "$s" timeout 90 "$ROOT/scanner.sh" scan "$TARGET_MS2" --quick >"$s/scan2.log" 2>&1
    a2="$(ls -1dt "$from"/assessment_* 2>/dev/null | head -n1)"
    n="$(ls -1d "$from"/assessment_* 2>/dev/null | wc -l)"
    note "t83 second scan creates a distinct assessment (2 total)"
    if [[ -n "$a1" && -n "$a2" && "$a1" != "$a2" && "$n" == 2 ]]; then pass; else fail "assessment reused or count=$n" "t83 distinct"; fi

    note "t83 first assessment byte-identical after second scan"
    if [[ "$snap1" == "$(find "$a1" -type f 2>/dev/null | sort | sed 's#.*/##'; cat "$a1/manifest.json")" ]]; then pass; else fail "first assessment mutated" "t83 immutability"; fi

    aid1="$(basename "$a1")"
    ux "$s" timeout 120 "$ROOT/scanner.sh" resume "$aid1" >"$s/resume.log" 2>&1
    manifest_has_phase "t83 resumed vulnerabilities" "$a1/manifest.json" vulnerabilities
    manifest_has_phase "t83 resumed report" "$a1/manifest.json" report
    local a2files
    a2files="$(find "$a2/vulnerabilities" -type f 2>/dev/null | wc -l)"
    note "t83 resume of a1 leaves a2 untouched"
    if [[ "$a2files" == 0 ]]; then pass; else fail "a2 mutated by a1 resume ($a2files files)" "t83 isolation"; fi

    local mh1 mh2
    mh1="$(sha1sum "$a1/manifest.json" | awk '{print $1}')"
    ux "$s" timeout 60 "$ROOT/scanner.sh" scope create "$aid1" 192.168.1.9 --name extra >"$s/scope.log" 2>&1
    mh2="$(sha1sum "$a1/manifest.json" | awk '{print $1}')"
    note "t83 scope create on existing assessment leaves manifest untouched"
    if [[ "$mh1" == "$mh2" ]]; then pass; else fail "manifest changed by scope create" "t83 scope"; fi
    assert_not_contains "t83 no recreate message for existing assessment" "created: $aid1" "$s/scope.log"
}

# ------------------------------------------------------------------
# Phase-failure -> pipeline-failure exit-code propagation (set -euo pipefail).
# ------------------------------------------------------------------

t84_pipeline_error_propagation() {
    local s="$RUN/t84"
    mkdir -p "$s"
    local from="$s/assessments" rc

    # Legacy single phase: no enumeration data -> module rc=2 must reach the CLI.
    ux "$s" timeout 60 "$ROOT/scanner.sh" "$TARGET_NOART" vulnerabilities >"$s/legacy.log" 2>&1; rc=$?
    note "t84 legacy single-phase failure propagates rc=2"
    if [[ "$rc" == 2 ]]; then pass; else fail "legacy vuln rc=$rc" "t84 legacy"; fi

    # Assessment resume: poison the assessment-scoped XML so the vulnerabilities
    # phase fails; resume must exit nonzero, record the failed phase, and still
    # produce an honest report.
    ux "$s" timeout 90 "$ROOT/scanner.sh" scan "$TARGET_MS2" --quick >"$s/scan.log" 2>&1
    local aid dir xml
    aid="$(ls -1dt "$from"/assessment_* 2>/dev/null | head -n1 | xargs basename)"
    dir="$from/$aid"
    for xml in "$dir"/enumeration/*.xml; do
        [[ -f "$xml" ]] && printf '<broken' > "$xml"
    done
    ux "$s" timeout 150 "$ROOT/scanner.sh" resume "$aid" >"$s/resume.log" 2>&1; rc=$?
    note "t84 failing phase propagates nonzero resume rc"
    if [[ "$rc" != 0 ]]; then pass; else fail "resume rc=0 despite phase failure" "t84 resume"; fi
    manifest_no_phase "t84 vulnerabilities not marked completed" "$dir/manifest.json" vulnerabilities
    assert_contains "t84 resume log notes phase error" "finished with exit code" "$s/resume.log"
    manifest_status "t84 resume status failed" "$dir/manifest.json" failed
}

# ------------------------------------------------------------------
# Bug 4 regression: legacy 'full' must forward extra arguments (e.g.
# --lhost) to Phase 5 exactly like standalone 'exploit' does. With the
# LHOST-requiring payload and no MFE_LHOST/LHOST, a forwarded --lhost
# satisfies the pre-approval LHOST check and stops at the approval prompt
# on EOF (rc=5); a dropped argument would abort earlier with rc=1.
# ------------------------------------------------------------------

t85_full_forwards_lhost() {
    local s="$RUN/t85"
    local t="203.0.113.85"
    mkdir -p "$s"

    local log1="$s/run1.log" rc1
    printf '1\n' | ux "$s" timeout 180 env -u MFE_LHOST -u LHOST \
        FAKE_MSF_LHOST_REQUIRED=1 \
        bash -c '"$0" '"$t"' full --lhost 192.168.1.10' "$ROOT/scanner.sh" \
        >"$log1" 2>&1; rc1=$?
    note "t85 full --lhost reaches approval (rc=5, not rc=1)"
    if [[ "$rc1" == 5 ]]; then pass; else fail "expected rc=5, got rc=$rc1" "t85 rc1"; fi
    assert_contains "t85 probe confirms LHOST required" "LHOST -> required by the (effective) payload" "$log1"
    assert_not_contains "t85 LHOST satisfied pre-launch, no abort" "requires LHOST" "$log1"
    assert_contains "t85 stops at approval prompt on EOF" "No input available - exploitation cancelled." "$log1"

    local log2="$s/run2.log" rc2
    printf '1\n' | ux "$s" timeout 180 env -u MFE_LHOST -u LHOST \
        FAKE_MSF_LHOST_REQUIRED=1 \
        bash -c '"$0" '"$t"' full' "$ROOT/scanner.sh" \
        >"$log2" 2>&1; rc2=$?
    note "t85 full without --lhost fails honestly (rc=1)"
    if [[ "$rc2" == 1 ]]; then pass; else fail "expected rc=1, got rc=$rc2" "t85 rc2"; fi
    assert_contains "t85 missing-LHOST guidance shown" "requires LHOST" "$log2"
}

# ------------------------------------------------------------------
# Exploitation execution-path regressions:
#  * follow-up commands must never print '././scanner.sh'
#  * CLI --lhost must reach Phase 5 through the legacy path (and full)
#  * menu option 8 must share the same execution path / LHOST handling
#  * assessment-scoped exploitation must stay inside the assessment dir
#  * dry-run must be completely non-executing
# ------------------------------------------------------------------

t86_exploit_followup_commands() {
    local s="$RUN/t86"
    local t="203.0.113.86"
    mkdir -p "$s/vuln/${t}_1"
    _write_corr "$s/vuln/${t}_1" "$t"

    # A: decline approval -> rc=5; the legacy exploit branch prints the
    # follow-up commands with a single './' prefix, never '././'.
    local logA="$s/runA.log" rcA
    printf '1\nn\n' | ux "$s" timeout 120 bash -c '"$0" '"$t"' exploit' ./scanner.sh >"$logA" 2>&1; rcA=$?
    note "t86 declined exploit still exits 5"
    if [[ "$rcA" == 5 ]]; then pass; else fail "expected rc=5, got rc=$rcA" "t86 rcA"; fi
    assert_contains "t86 follow-up evidence cmd" "./scanner.sh $t evidence" "$logA"
    assert_contains "t86 follow-up report cmd" "./scanner.sh $t report" "$logA"
    assert_not_contains "t86 no doubled ./ prefix" "././scanner.sh" "$logA"
    assert_contains "t86 approval gate active (denied by user)" "Exploitation not approved - cancelled." "$logA"

    # B: dry-run must not ask for approval, launch, or write artifacts.
    local logB="$s/runB.log" rcB
    printf '1\n' | ux "$s" timeout 120 bash -c '"$0" '"$t"' exploit --dry-run' ./scanner.sh >"$logB" 2>&1; rcB=$?
    note "t86 dry-run does not execute"
    if [[ "$rcB" == 0 ]]; then pass; else fail "dry-run rc=$rcB" "t86 rcB"; fi
    assert_contains "t86 dry-run plan shown" "DRY-RUN" "$logB"
    assert_not_contains "t86 dry-run never asks approval" "Run this exploit against" "$logB"
    note "t86 dry-run leaves no exploit artifacts"
    if [[ -z "$(latest_dir "$s/exploit/${t}_" 2>/dev/null)" ]]; then pass; else fail "dry-run wrote artifacts" "t86 dryart"; fi
}

t87_legacy_exploit_lhost() {
    local s="$RUN/t87"
    local t="203.0.113.87"
    mkdir -p "$s/vuln/${t}_1"
    _write_corr "$s/vuln/${t}_1" "$t"

    # A: --lhost is the only LHOST source; explicit approval launches the
    # fake exploit, which returns a modelled session with that LHOST.
    local logA="$s/runA.log" rcA xd
    printf '1\ny\n' | ux "$s" timeout 120 env -u MFE_LHOST -u LHOST FAKE_MSF_LHOST_REQUIRED=1 \
        OUTPUT_EXPLOIT="$s/exploitA" \
        bash -c '"$0" '"$t"' exploit --lhost 192.168.1.10' ./scanner.sh >"$logA" 2>&1; rcA=$?
    note "t87 cli --lhost reachs exploitation and approves (rc=0)"
    if [[ "$rcA" == 0 ]]; then pass; else fail "expected rc=0, got rc=$rcA" "t87 rcA"; fi
    assert_contains "t87 probe sees LHOST required" "LHOST -> required by the (effective) payload" "$logA"
    assert_not_contains "t87 lhost accepted, no missing-lhost abort" "requires LHOST" "$logA"
    xd="$(latest_dir "$s/exploitA/${t}_")"
    assert_contains "t87 recorded effective lhost" "lhost=192.168.1.10" "$xd/result.txt"
    assert_contains "t87 real session required for success" "session_status=session-created" "$xd/result.txt"
    assert_contains "t87 launch resource carries set LHOST" "set LHOST 192.168.1.10" "$xd/msf_resource.res"

    # B: LHOST required by the payload but nowhere configured -> honest
    # pre-launch failure, no launch, no artifacts.
    local logB="$s/runB.log" rcB
    printf '1\n' | ux "$s" timeout 120 env -u MFE_LHOST -u LHOST FAKE_MSF_LHOST_REQUIRED=1 \
        OUTPUT_EXPLOIT="$s/exploitB" \
        bash -c '"$0" '"$t"' exploit' ./scanner.sh >"$logB" 2>&1; rcB=$?
    note "t87 missing lhost fails honestly (rc=1) before launch"
    if [[ "$rcB" == 1 ]]; then pass; else fail "expected rc=1, got rc=$rcB" "t87 rcB"; fi
    assert_contains "t87 missing-LHOST guidance" "requires LHOST" "$logB"
    note "t87 no artifact written without a lhost"
    if [[ -z "$(latest_dir "$s/exploitB/${t}_" 2>/dev/null)" ]]; then pass; else fail "exploit launched without lhost" "t87 runB"; fi

    # C: the target address as --lhost is rejected before launch.
    local logC="$s/runC.log" rcC
    printf '1\n' | ux "$s" timeout 120 env -u MFE_LHOST -u LHOST FAKE_MSF_LHOST_REQUIRED=1 \
        OUTPUT_EXPLOIT="$s/exploitC" \
        bash -c '"$0" '"$t"' exploit --lhost '"$t" ./scanner.sh >"$logC" 2>&1; rcC=$?
    note "t87 target as lhost rejected"
    if [[ "$rcC" == 1 ]]; then pass; else fail "expected rc=1, got rc=$rcC" "t87 rcC"; fi
    assert_contains "t87 target-as-lhost refused" "must not be the target address" "$logC"
}

t88_menu_exploit_lhost() {
    local s="$RUN/t88"
    local t="203.0.113.88"
    mkdir -p "$s/vuln/${t}_1"
    _write_corr "$s/vuln/${t}_1" "$t"

    # Option 8 delegates to the SAME legacy path ('<scanner> <target> exploit'),
    # so the configured LHOST (MFE_LHOST here, since the menu has no LHOST
    # prompt) is respected end-to-end.
    local log="$s/menu.log" rc xd
    printf '8\n%s\n1\ny\n0\n' "$t" | ux "$s" timeout 150 env FAKE_MSF_LHOST_REQUIRED=1 \
        MFE_LHOST=192.168.1.99 "$ROOT/scanner.sh" menu >"$log" 2>&1; rc=$?
    note "t88 menu exploitation returns rc=0"
    if [[ "$rc" == 0 ]]; then pass; else fail "menu rc=$rc" "t88 rc"; fi
    xd="$(latest_dir "$s/exploit/${t}_")"
    assert_file "t88 menu result.txt" "$xd/result.txt"
    assert_contains "t88 menu session created" "session_status=session-created" "$xd/result.txt"
    assert_contains "t88 menu kept configured lhost" "lhost=192.168.1.99" "$xd/result.txt"
    assert_contains "t88 menu launch resource set LHOST" "set LHOST 192.168.1.99" "$xd/msf_resource.res"
}

t89_assessment_exploit_isolation() {
    local s="$RUN/t89"
    local t="203.0.113.89"
    mkdir -p "$s"
    local log="$s/scan.log" rc aid m xp
    printf '1\ny\n' | ux "$s" timeout 200 bash -c '"$0" scan '"$t"' --full' "$ROOT/scanner.sh" >"$log" 2>&1; rc=$?
    note "t89 assessment full scan rc=0"
    if [[ "$rc" == 0 ]]; then pass; else fail "scan rc=$rc" "t89 rc"; fi
    aid="$(ls -1dt "$s/assessments"/assessment_* 2>/dev/null | head -n1 | xargs basename)"
    m="$s/assessments/$aid/manifest.json"
    manifest_status "t89 manifest completed" "$m" completed
    xp="$(ls -1dt "$s/assessments/$aid/exploitation"/*/result.txt 2>/dev/null | head -n1)"
    assert_file "t89 exploitation result inside assessment" "$xp"
    assert_contains "t89 assessment session recorded" "session_status=session-created" "$xp"
    note "t89 no legacy exploitation fallback"
    if [[ -z "$(ls -A "$s/exploit" 2>/dev/null)" ]]; then pass; else fail "exploitation escaped to legacy dir" "t89 legacy"; fi
}

# ------------------------------------------------------------------
# Bug 2 regression: Metasploit runner capability probing (payload /
# ExitOnSession / LHOST), session-gated evidence, honest timeouts, dry-run.
# The fake msfconsole simulates a release Metasploit that rejects
# cmd/unix/interact, warns on ExitOnSession, and (on demand) requires LHOST.
# ------------------------------------------------------------------

t69_exploit_invalid_payload_fallback() {
    local s="$RUN/t69"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.69"
    _write_corr "$src" "$t"
    mkdir -p "$xd"
    local log="$s/run.log" d rc
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        OUTPUT_EXPLOIT="$xd" "$MODULES/exploitation.sh" "$t" "$src" 1 >"$log" 2>&1; rc=$?
    note "t69 invalid payload falls back to module default -> session rc=0"
    if [[ "$rc" == 0 ]]; then pass; else fail "expected rc=0, got rc=$rc" "t69 rc"; fi
    d="$(latest_dir "$xd/${t}_")"
    assert_contains "t69 payload rejected by build" "payload_valid=no" "$d/result.txt"
    assert_contains "t69 module default used" "payload_used=module-default" "$d/result.txt"
    assert_not_contains "t69 unsupported ExitOnSession never sent" "set ExitOnSession" "$d/msf_resource.res"
    assert_not_contains "t69 invalid PAYLOAD never sent" "set PAYLOAD" "$d/msf_resource.res"
    assert_not_contains "t69 no legacy sessions -C in launch script" "sessions -C" "$d/msf_resource.res"
    assert_contains "t69 evidence via detected session only" "SAT_USER_START" "$d/exploit_output.txt"
    assert_file "t69 evidence resource saved" "$d/msf_evidence.res"
}

t70_exploit_lhost_required_missing() {
    local s="$RUN/t70"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.70"
    _write_corr "$src" "$t"
    mkdir -p "$xd"
    local log="$s/run.log" rc
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        FAKE_MSF_LHOST_REQUIRED=1 OUTPUT_EXPLOIT="$xd" \
        "$MODULES/exploitation.sh" "$t" "$src" 1 >"$log" 2>&1; rc=$?
    note "t70 LHOST required but unset -> rc=1, aborts before any launch"
    if [[ "$rc" == 1 ]]; then pass; else fail "expected rc=1, got rc=$rc" "t70 rc"; fi
    assert_contains "t70 clear LHOST guidance" "requires LHOST" "$log"
    note "t70 no exploitation output dir"
    if [[ -z "$(latest_dir "$xd/${t}_" 2>/dev/null)" ]]; then pass; else fail "exploitation ran without LHOST" "t70 ran"; fi
}

t71_exploit_lhost_provided() {
    local s="$RUN/t71"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.71"
    _write_corr "$src" "$t"
    mkdir -p "$xd"
    local log="$s/run.log" d rc
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        FAKE_MSF_LHOST_REQUIRED=1 MFE_LHOST=192.168.1.99 OUTPUT_EXPLOIT="$xd" \
        "$MODULES/exploitation.sh" "$t" "$src" 1 >"$log" 2>&1; rc=$?
    note "t71 LHOST configured -> runs and opens session rc=0"
    if [[ "$rc" == 0 ]]; then pass; else fail "expected rc=0, got rc=$rc" "t71 rc"; fi
    d="$(latest_dir "$xd/${t}_")"
    assert_contains "t71 LHOST sent to resource" "set LHOST 192.168.1.99" "$d/msf_resource.res"
    assert_contains "t71 result records lhost" "lhost=192.168.1.99" "$d/result.txt"
    assert_contains "t71 session created" "session_status=session-created" "$d/result.txt"

    local log2="$s/run2.log" d2 rc2
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        FAKE_MSF_LHOST_REQUIRED=1 MFE_LHOST=192.168.1.99 OUTPUT_EXPLOIT="$xd" \
        "$MODULES/exploitation.sh" "$t" "$src" 1 --lhost 10.9.9.9 >"$log2" 2>&1; rc2=$?
    note "t71 --lhost CLI wins over MFE_LHOST"
    if [[ "$rc2" == 0 ]]; then pass; else fail "expected rc=0, got rc=$rc2" "t71 rc2"; fi
    d2="$(latest_dir "$xd/${t}_")"
    assert_contains "t71 --lhost precedence" "set LHOST 10.9.9.9" "$d2/msf_resource.res"
}

t72_exploit_lhost_never_target() {
    local s="$RUN/t72"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.72"
    _write_corr "$src" "$t"
    mkdir -p "$xd"
    local log="$s/run.log" rc
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        FAKE_MSF_LHOST_REQUIRED=1 MFE_LHOST="$t" OUTPUT_EXPLOIT="$xd" \
        "$MODULES/exploitation.sh" "$t" "$src" 1 >"$log" 2>&1; rc=$?
    note "t72 target address forbidden as LHOST -> rc=1"
    if [[ "$rc" == 1 ]]; then pass; else fail "expected rc=1, got rc=$rc" "t72 rc"; fi
    assert_contains "t72 target-as-LHOST rejected" "must not be the target address" "$log"
    note "t72 no exploitation output dir"
    if [[ -z "$(latest_dir "$xd/${t}_" 2>/dev/null)" ]]; then pass; else fail "exploitation ran with target LHOST" "t72 ran"; fi
}

t73_exploit_timeout_not_success() {
    local s="$RUN/t73"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.73"
    _write_corr "$src" "$t"
    mkdir -p "$xd"
    local log="$s/run.log" d rc
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        FAKE_MSF_HANG=1 MFE_TIMEOUT=3 OUTPUT_EXPLOIT="$xd" \
        "$MODULES/exploitation.sh" "$t" "$src" 1 >"$log" 2>&1; rc=$?
    note "t73 timeout is a failure, never success rc=2"
    if [[ "$rc" == 2 ]]; then pass; else fail "expected rc=2, got rc=$rc" "t73 rc"; fi
    d="$(latest_dir "$xd/${t}_")"
    assert_contains "t73 timeout recorded honestly" "msfconsole_timeout=yes" "$d/result.txt"
    assert_contains "t73 timeout not success" "session_status=no-session" "$d/result.txt"
}

t74_exploit_no_session_no_evidence() {
    local s="$RUN/t74"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.74"
    _write_corr "$src" "$t"
    mkdir -p "$xd"
    local log="$s/run.log" d rc
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        OUTPUT_EXPLOIT="$xd" "$MODULES/exploitation.sh" "$t" "$src" 2 >"$log" 2>&1; rc=$?
    note "t74 no-session is rc=2 and never fabricates a session"
    if [[ "$rc" == 2 ]]; then pass; else fail "expected rc=2, got rc=$rc" "t74 rc"; fi
    d="$(latest_dir "$xd/${t}_")"
    assert_contains "t74 session_id none" "session_id=none" "$d/status.txt"
    assert_contains "t74 no-session result" "session_status=no-session" "$d/result.txt"
    note "t74 no evidence resource created without a session"
    if [[ ! -f "$d/msf_evidence.res" ]]; then pass; else fail "evidence collected without session" "t74 evidence"; fi
    assert_not_contains "t74 evidence markers never fabricated" "SAT_HOSTNAME_START" "$d/exploit_output.txt"
}

t75_exploit_dry_run() {
    local s="$RUN/t75"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.75"
    _write_corr "$src" "$t"
    mkdir -p "$xd"
    local log="$s/run.log" rc
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        OUTPUT_EXPLOIT="$xd" "$MODULES/exploitation.sh" "$t" "$src" 1 --dry-run >"$log" 2>&1; rc=$?
    note "t75 dry-run exits 0 with no execution and no artifacts"
    if [[ "$rc" == 0 ]]; then pass; else fail "expected rc=0, got rc=$rc" "t75 rc"; fi
    assert_contains "t75 dry-run notice" "DRY-RUN" "$log"
    assert_contains "t75 dry-run shows plan" "exploit -j -z" "$log"
    note "t75 dry-run writes nothing"
    if [[ -z "$(latest_dir "$xd/${t}_" 2>/dev/null)" ]]; then pass; else fail "dry-run produced output dir" "t75 artifacts"; fi
}

t76_exploit_launch_failure_honest() {
    local s="$RUN/t76"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.76"
    _write_corr "$src" "$t"
    mkdir -p "$xd"
    local log="$s/run.log" d rc
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        FAKE_MSF_FAIL=1 OUTPUT_EXPLOIT="$xd" \
        "$MODULES/exploitation.sh" "$t" "$src" 1 >"$log" 2>&1; rc=$?
    note "t76 msf launch failure -> honest no-session rc=2"
    if [[ "$rc" == 2 ]]; then pass; else fail "expected rc=2, got rc=$rc" "t76 rc"; fi
    d="$(latest_dir "$xd/${t}_")"
    assert_contains "t76 msf exit code recorded" "msfconsole_exit=1" "$d/result.txt"
    assert_contains "t76 failure never success" "session_status=no-session" "$d/result.txt"
}

t91_exploit_evidence_same_session() {
    local s="$RUN/t91"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.91"
    _write_corr "$src" "$t"
    mkdir -p "$xd"
    local log="$s/run.log" d rc
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        OUTPUT_EXPLOIT="$xd" "$MODULES/exploitation.sh" "$t" "$src" 1 >"$log" 2>&1; rc=$?
    note "t91 evidence collected via the SAME live session rc=0"
    if [[ "$rc" == 0 ]]; then pass; else fail "expected rc=0, got rc=$rc" "t91 rc"; fi
    d="$(latest_dir "$xd/${t}_")"
    assert_contains "t91 session created" "session_status=session-created" "$d/result.txt"
    assert_contains "t91 session id from msf output" "session_id=1" "$d/result.txt"
    assert_contains "t91 evidence collected" "evidence_status=collected" "$d/result.txt"
    # The session announcement AND the evidence markers share one file/process:
    # the single live msfconsole that both launched the exploit and collected
    # the evidence through its own stdin before terminating.
    assert_contains "t91 session announced in same output" "Command shell session 1 opened" "$d/exploit_output.txt"
    assert_contains "t91 evidence markers in same output" "SAT_EVIDENCE_END" "$d/exploit_output.txt"
    assert_contains "t91 hostname collected" "hostname_status=collected" "$d/result.txt"
    assert_contains "t91 OS collected" "system_status=collected" "$d/result.txt"
    assert_file "t91 evidence resource saved for the real id" "$d/msf_evidence.res"
    assert_contains "t91 evidence note" "evidence captured through the same live session" "$d/result.txt"
    # The launch script stays alive (no self-terminate) and contains no
    # separate evidence stage - it is the same process all the way through.
    assert_not_contains "t91 launch script never exits itself" "exit -y" "$d/msf_resource.res"
    assert_not_contains "t91 launch script has no detached evidence run" "sessions -c" "$d/msf_resource.res"
}

t92_exploit_evidence_failure_is_honest() {
    local s="$RUN/t92"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.92"
    _write_corr "$src" "$t"
    mkdir -p "$xd"

    # a) the session exists but the evidence command itself fails - the
    #    exploitation must stay a success while the evidence records failure.
    local log="$s/run_a.log" d rc
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        FAKE_MSF_EVIDENCE_FAIL=1 MFE_SESSION_WAIT=1 OUTPUT_EXPLOIT="$xd" \
        "$MODULES/exploitation.sh" "$t" "$src" 1 >"$log" 2>&1; rc=$?
    note "t92a evidence failure keeps exploitation success rc=0"
    if [[ "$rc" == 0 ]]; then pass; else fail "expected rc=0, got rc=$rc" "t92a rc"; fi
    d="$(latest_dir "$xd/${t}_")"
    assert_contains "t92a session still created" "session_status=session-created" "$d/result.txt"
    assert_contains "t92a failure recorded separately" "evidence_status=failed" "$d/result.txt"
    assert_contains "t92a hostname failure honest" "hostname_status=failed" "$d/result.txt"
    assert_contains "t92a msf reported the command error" "Error executing command" "$d/exploit_output.txt"
    assert_not_contains "t92a no fabricated evidence markers" "SAT_EVIDENCE_END" "$d/exploit_output.txt"
    assert_not_contains "t92a no fabricated hostname" "SAT_HOSTNAME_START" "$d/exploit_output.txt"

    # b) no session at all -> evidence is never attempted and rc stays 2.
    local log2="$s/run_b.log" d2 rc2
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        MFE_SESSION_WAIT=1 OUTPUT_EXPLOIT="$xd" \
        "$MODULES/exploitation.sh" "$t" "$src" 2 >"$log2" 2>&1; rc2=$?
    note "t92b no session -> evidence not attempted rc=2"
    if [[ "$rc2" == 2 ]]; then pass; else fail "expected rc=2, got rc=$rc2" "t92b rc"; fi
    d2="$(latest_dir "$xd/${t}_")"
    assert_contains "t92b no-session result" "session_status=no-session" "$d2/result.txt"
    assert_contains "t92b evidence not attempted" "evidence_status=not-attempted" "$d2/result.txt"
    note "t92b no evidence resource without a session"
    if [[ ! -f "$d2/msf_evidence.res" ]]; then pass; else fail "evidence resource without session" "t92b evidence"; fi
    assert_not_contains "t92b no fabricated markers" "SAT_HOSTNAME_START" "$d2/exploit_output.txt"
}

t63_exploit_mapping_before_approval() {
    local s="$RUN/t63"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.68"
    _write_corr "$src" "$t"
    mkdir -p "$xd"
    # Unmapped candidate (Apache Jserv, index 3): approval must NEVER be
    # requested and no Metasploit run may follow (exit 4).
    local log="$s/run.log" rc
    printf 'y\n' | env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf" \
        OUTPUT_EXPLOIT="$xd" "$MODULES/exploitation.sh" "$t" "$src" 3 >"$log" 2>&1; rc=$?
    note "t63 unmapped candidate rc=4"
    if [[ "$rc" == 4 ]]; then pass; else fail "expected rc=4, got rc=$rc" "t63 rc"; fi
    assert_contains "t63 mapping-not-found reported" "No Metasploit module mapping configured" "$log"
    assert_not_contains "t63 no approval prompt for unmapped" "Run this exploit" "$log"
    note "t63 no exploitation output produced"
    if [[ -z "$(latest_dir "$xd/${t}_" 2>/dev/null)" ]]; then pass; else fail "exploitation ran without mapping" "t63 ran"; fi
}

t64_exploit_filters() {
    local s="$RUN/t64"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.70"
    _write_corr "$src" "$t"
    mkdir -p "$xd"
    local common=(env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf"
        OUTPUT_EXPLOIT="$xd" MFE_FILTER_THRESHOLD=100 "$MODULES/exploitation.sh" "$t" "$src")

    local log rc n
    log="$s/risk.log"
    printf 'q\n' | "${common[@]}" --risk high >"$log" 2>&1; rc=$?
    note "t64 --risk high reaches selection (rc=5 cancelled)"
    if [[ "$rc" == 5 ]]; then pass; else fail "expected rc=5, got rc=$rc" "t64 risk rc"; fi
    n="$(grep -cE '^\[[0-9]+\]' "$log")"
    note "t64 --risk high shows only the 1 high candidate (vsftpd)"
    if [[ "$n" == 1 ]]; then pass; else fail "expected 1 high candidate, got $n" "$log"; fi
    assert_contains "t64 high includes vsftpd" "17491" "$log"
    assert_not_contains "t64 high excludes medium samba" "16320" "$log"

    log="$s/port.log"
    printf 'q\n' | "${common[@]}" --port 139 >"$log" 2>&1; rc=$?
    note "t64 --port 139 filtered rc=5"
    if [[ "$rc" == 5 ]]; then pass; else fail "expected rc=5, got rc=$rc" "t64 port rc"; fi
    n="$(grep -cE '^\[[0-9]+\]' "$log")"
    note "t64 --port 139 shows only the samba candidate"
    if [[ "$n" == 1 ]]; then pass; else fail "expected 1 candidate, got $n" "$log"; fi
    assert_contains "t64 port 139 is samba" "16320" "$log"
    assert_not_contains "t64 port 139 excludes vsftpd" "17491" "$log"

    log="$s/edb.log"
    printf 'q\n' | "${common[@]}" --edb-id 16320 >"$log" 2>&1; rc=$?
    note "t64 --edb-id 16320 filtered rc=5"
    if [[ "$rc" == 5 ]]; then pass; else fail "expected rc=5, got rc=$rc" "t64 edb rc"; fi
    n="$(grep -cE '^\[[0-9]+\]' "$log")"
    note "t64 --edb-id 16320 shows only EDB-16320"
    if [[ "$n" == 1 ]]; then pass; else fail "expected 1 candidate, got $n" "$log"; fi
    assert_contains "t64 edb row is samba" "Username map script" "$log"

    # Positional candidate index selects directly (no interactive listing choice).
    log="$s/idx.log"
    printf '2\nn\n' | "${common[@]}" >"$log" 2>&1; rc=$?
    note "t64 positional index 2 selects samba (approval n -> rc=5)"
    if [[ "$rc" == 5 ]]; then pass; else fail "expected rc=5, got rc=$rc" "t64 idx rc"; fi
    assert_contains "t64 index 2 selected the samba candidate" "Username map script" "$log"
    assert_not_contains "t64 index 2 selection not vsftpd" "Selected: vsftpd" "$log"

    log="$s/range.log"
    "${common[@]}" 99 >"$log" 2>&1; rc=$?
    note "t64 out-of-range index rc=4"
    if [[ "$rc" == 4 ]]; then pass; else fail "expected rc=4, got rc=$rc" "t64 range rc"; fi
}

t65_exploit_large_list_menu() {
    local s="$RUN/t65"
    local src="$s/src"
    local xd="$s/exploit"
    local t="203.0.113.71"
    _write_corr "$src" "$t"
    mkdir -p "$xd"
    local common=(env PATH="$FAKES:$BASE_PATH" CONFIG_FILE="$FIXTURES/config.conf"
        OUTPUT_EXPLOIT="$xd" "$MODULES/exploitation.sh" "$t" "$src")

    local log="$s/menu.log" rc
    printf '2\n1\nn\n' | MFE_FILTER_THRESHOLD=2 "${common[@]}" >"$log" 2>&1; rc=$?
    note "t65 large-list filter menu shown (rc=5 cancelled at approval)"
    if [[ "$rc" == 5 ]]; then pass; else fail "expected rc=5, got rc=$rc" "t65 menu rc"; fi
    assert_contains "t65 menu offered interactive filter" "Candidate list is large" "$log"
    assert_contains "t65 menu filter choice applied" "Filter:   risk=medium" "$log"

    printf 'q\n' | MFE_FILTER_THRESHOLD=100 "${common[@]}" >"$log" 2>&1; rc=$?
    note "t65 default threshold keeps menu suppressed (rc=5 cancelled)"
    if [[ "$rc" == 5 ]]; then pass; else fail "expected rc=5, got rc=$rc" "t65 plain rc"; fi
    assert_not_contains "t65 menu not shown under threshold" "Filter before selection" "$log"
}

t66_scanner_exploit_forward() {
    local s="$RUN/t66"
    local t="203.0.113.77"
    mkdir -p "$s/vuln/${t}_1"
    _write_corr "$s/vuln/${t}_1" "$t"
    # Legacy cmd path must forward candidate filters to the exploitation module.
    run_expect "t66 scanner exploit --edb-id forwarded (approval n -> 5)" 5 \
        ux "$s" bash -c 'printf "1\nn\n" | "$0" "$1" exploit --edb-id 16320' "$ROOT/scanner.sh" "$t"
    local xdir
    xdir="$(latest_dir "$s/exploit/${t}_")"
    note "t66 exploitation result not created (approval declined before run)"
    if [[ -z "$xdir" ]]; then pass; else fail "exploitation ran unexpectedly" "$xdir"; fi
}

# ------------------------------------------------------------------
# main / collection
# ------------------------------------------------------------------

cd "$ROOT" || exit 1

# Optional focused run - dev aid: TESTS="t13_exploit_no_session t14_exploit_session" ./tests/test_tool.sh
if [[ -n "${TESTS:-}" ]]; then
    echo "=================================================="
    echo " FOCUSED RUN (TESTS=$TESTS)"
    echo "=================================================="
    for t in $TESTS; do
        if [[ "$(type -t "$t")" == "function" ]]; then
            "$t"
        else
            echo "unknown test: $t"
        fi
    done
    echo "=================================================="
    echo " RESULTS: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
    echo "=================================================="
    if (( FAIL > 0 )); then exit 1; fi
    echo "ALL TESTS PASSED"
    exit 0
fi

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
t78_quick_scan_next_step
t38_status
t39_preflight
t40_corrupt_manifest
t79_scope_create_name
t80_scope_create_cidr
t81_scope_create_dedupe_hostname
t82_scope_list_show_status
t83_assessment_reuse_immutability
t84_pipeline_error_propagation
t85_full_forwards_lhost
t86_exploit_followup_commands
t87_legacy_exploit_lhost
t88_menu_exploit_lhost
t89_assessment_exploit_isolation
t91_exploit_evidence_same_session
t92_exploit_evidence_failure_is_honest

t41_enum_v2_normal
t42_enum_v2_no_open
t43_enum_v2_malformed_xml
t44_enum_v2_nmap_failure
t45_enum_v2_invalid_target
t46_enum_v2_missing_nmap
t47_enum_v2_port_modes
t48_enum_v2_scripts_safety
t49_enum_full_scan_safety

t50_enum_artifact_both
t51_enum_artifact_stage1_only
t52_enum_artifact_partial_missing
t53_enum_artifact_multiple_historical
t54_enum_artifact_legacy_no_status
t55_vuln_autoselect_stage2
t56_report_uses_stage2_text
t57_searchsploit_colour_modern
t58_searchsploit_colour_legacy
t59_searchsploit_colour_plain
t60_searchsploit_failure_not_fabricated

t61_corr_version_semantics
t62_corr_product_specificity
t67_corr_wildcard_versions
t68_enum_xml_resolution
t69_exploit_invalid_payload_fallback
t70_exploit_lhost_required_missing
t71_exploit_lhost_provided
t72_exploit_lhost_never_target
t73_exploit_timeout_not_success
t74_exploit_no_session_no_evidence
t75_exploit_dry_run
t76_exploit_launch_failure_honest
t63_exploit_mapping_before_approval
t64_exploit_filters
t65_exploit_large_list_menu
t66_scanner_exploit_forward

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