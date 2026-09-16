#!/usr/bin/env bash
#
# Phase 7 - Reporting
#
# Usage:
#   ./modules/report.sh <target>
#
# Builds a factual markdown (+ optional HTML) assessment report from the
# artifacts actually produced by Phases 1-6 for the given target.
# Missing phases are marked as "not performed" - never invented.
#
# Report sections:
#   1  Executive Summary
#   2  Target Information
#   3  Discovery Results
#   4  Open Ports
#   5  Services and Versions
#   6  Vulnerability Research
#   7  Correlated Findings
#   8  Exploit Candidates
#   9  Exploitation Results
#   10 Evidence
#   11 Limitations
#   12 Recommendations
#
# Exit codes:
#   0  report generated
#   1  usage/technical error
#   2  no phase data at all for the target

set -uo pipefail

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=lib/common.sh
source "$COMMON_DIR/common.sh"

EXIT_OK=0
EXIT_ERROR=1
EXIT_NO_DATA=2

usage() {
    echo "Usage: $0 <target>"
    echo "Example: $0 192.168.56.101"
}

TARGET="${1:-}"
if [[ -z "$TARGET" ]] || ! sat_validate_target "$TARGET"; then
    usage
    exit "$EXIT_ERROR"
fi

sat_load_config || exit "$EXIT_ERROR"
sat_apply_defaults

SAFE_TARGET="$(sat_safe_name "$TARGET")"
if ! sat_require_python3; then
    echo "[-] python3 required for report assembly." >&2
    exit "$EXIT_ERROR"
fi

# ---------------------------------------------------------------
# Locate the latest per-phase artifacts for the target
# ---------------------------------------------------------------

DISCOVERY_FILE="$(sat_latest_file "$OUTPUT_NMAP/${SAFE_TARGET}_"*.txt)"
ENUM_TXT="$(sat_latest_file "$OUTPUT_ENUM/${SAFE_TARGET}_"*.txt)"
ENUM_XML="$(sat_latest_file "$OUTPUT_ENUM/${SAFE_TARGET}_"*.xml)"

VULN_RESEARCH_DIR=""
CORRELATION_DIR=""
if [[ -d "$OUTPUT_VULN" ]]; then
    local_dir=""
    for local_dir in "$OUTPUT_VULN/${SAFE_TARGET}"_*; do
        [[ -d "$local_dir" ]] || continue
        if [[ -f "$local_dir/correlated_findings.tsv" ]]; then
            CORRELATION_DIR="$local_dir"
        elif [[ -f "$local_dir/services.tsv" ]]; then
            VULN_RESEARCH_DIR="$local_dir"
        fi
    done
fi

EXPLOIT_DIR="$(sat_latest_dir "$OUTPUT_EXPLOIT" "$SAFE_TARGET")"
EVIDENCE_DIR="$(sat_latest_dir "$OUTPUT_EVIDENCE" "$SAFE_TARGET")"

if [[ -z "$DISCOVERY_FILE" && -z "$ENUM_TXT" && -z "$VULN_RESEARCH_DIR" && -z "$CORRELATION_DIR" && -z "$EXPLOIT_DIR" && -z "$EVIDENCE_DIR" ]]; then
    echo "[-] No assessment data found for target '$TARGET'." >&2
    exit "$EXIT_NO_DATA"
fi

TIMESTAMP="$(sat_timestamp)"
REPORT_DIR="$OUTPUT_REPORTS"
mkdir -p "$REPORT_DIR"
MD_FILE="$REPORT_DIR/${SAFE_TARGET}_${TIMESTAMP}.md"
HTML_FILE="$REPORT_DIR/${SAFE_TARGET}_${TIMESTAMP}.html"

MD=""

md_append() { MD+="$1"$'\n'; }

# ---------------------------------------------------------------
# Section 1 - Executive Summary
# ---------------------------------------------------------------

EXEC_NOTES=""

HOST_STATE="unknown"
if [[ -n "$DISCOVERY_FILE" ]] && grep -q "Host is up" "$DISCOVERY_FILE"; then
    HOST_STATE="up"
elif [[ -n "$ENUM_TXT" ]] && grep -qE 'Host is up' "$ENUM_TXT"; then
    HOST_STATE="up"
fi

OPEN_COUNT=0
if [[ -n "$ENUM_TXT" ]]; then
    OPEN_COUNT="$(grep -cE '^[0-9]+/[0-9a-z]+[[:space:]]+open([[:space:]]|\|)' "$ENUM_TXT" || true)"
fi

FINDINGS_TOTAL=0
if [[ -n "$CORRELATION_DIR" && -f "$CORRELATION_DIR/status.txt" ]]; then
    FINDINGS_TOTAL="$(grep -E '^findings=' "$CORRELATION_DIR/status.txt" | cut -d= -f2 | head -n1 || true)"
    FINDINGS_TOTAL="${FINDINGS_TOTAL:-0}"
fi

SESSION_STATUS="not-performed"
if [[ -n "$EXPLOIT_DIR" && -f "$EXPLOIT_DIR/status.txt" ]]; then
    SESSION_STATUS="$(grep -E '^status=' "$EXPLOIT_DIR/status.txt" | cut -d= -f2 | head -n1 || true)"
fi

md_append "# $REPORT_TITLE"
md_append ""
md_append "**Target:** $TARGET  "
md_append "**Report generated:** $(date '+%Y-%m-%d %H:%M:%S %Z')  "
md_append "**Scope:** authorized Metasploitable 2 lab assessment only  "
md_append ""
md_append "## 1. Executive Summary"
md_append ""
if [[ "$HOST_STATE" == "up" ]]; then
    md_append "- The target host **$TARGET** was reachable during the assessment."
else
    md_append "- The target host **$TARGET** was **not** confirmed reachable during the assessed phases."
fi
md_append "- Open TCP services detected on scanned ports: **$OPEN_COUNT**."
md_append "- Correlated exploit-candidate findings: **$FINDINGS_TOTAL** (tool categorical assessment, not CVSS)."
if [[ "$SESSION_STATUS" == "session-created" ]]; then
    md_append "- Exploitation: a **session was created** in the authorized lab."
elif [[ "$SESSION_STATUS" == "no-session" ]]; then
    md_append "- Exploitation: attempted but **no session was created**."
else
    md_append "- Exploitation: **not performed**."
fi

# ---------------------------------------------------------------
# Section 2 - Target Information
# ---------------------------------------------------------------

md_append ""
md_append "## 2. Target Information"
md_append ""
md_append "| Field | Value |"
md_append "|---|---|"
md_append "| Target | $TARGET |"
md_append "| Assessment tool | security-assessment (bash-lab-toolkit) |"
if [[ -n "$ENUM_XML" ]]; then
    ADDR_ROWS="$(python3 - "$ENUM_XML" <<'PY'
import sys
import xml.etree.ElementTree as ET

try:
    root = ET.parse(sys.argv[1]).getroot()
    for host in root.findall('host'):
        for a in host.findall('address'):
            print("| %s | %s |" % (a.get('addrtype', 'address'), a.get('addr', '')))
        hn = host.find('hostnames/hostname')
        if hn is not None and hn.get('name'):
            print("| Hostname | %s |" % hn.get('name'))
except Exception:
    pass
PY
)"
    while IFS= read -r r; do
        [[ -n "$r" ]] && md_append "$r"
    done <<< "$ADDR_ROWS"
fi
md_append ""

if [[ -n "$ENUM_TXT" ]] && grep -qE '\bos match' "$ENUM_TXT"; then
    md_append "- OS detection reported by Nmap:"
    while IFS= read -r l; do md_append "    - $l"; done < <(grep -E 'OS (details|used|name)' "$ENUM_TXT")
fi

# ---------------------------------------------------------------
# Section 3 - Discovery Results
# ---------------------------------------------------------------

md_append "## 3. Discovery Results"
md_append ""
if [[ -n "$DISCOVERY_FILE" ]]; then
    md_append "- Source: $DISCOVERY_FILE"
    if grep -q "Host is up" "$DISCOVERY_FILE"; then
        md_append "- **Host $TARGET is UP** (responded to discovery probes)."
    else
        md_append "- **Host $TARGET is DOWN or filtering probes**."
    fi
else
    md_append "- Phase 1 (discovery) **not performed** for this target."
fi

# ---------------------------------------------------------------
# Section 4 - Open Ports
# ---------------------------------------------------------------

md_append ""
md_append "## 4. Open Ports"
md_append ""
if [[ -n "$ENUM_TXT" ]]; then
    md_append "| Port | State | Service | Version |"
    md_append "|---|---|---|---|"
    while IFS= read -r l; do
        port="$(awk '{print $1}' <<<"$l")"
        state="$(awk '{print $2}' <<<"$l")"
        service="$(awk '{print $3}' <<<"$l")"
        version="$(awk '{for(i=4;i<=NF;i++) printf "%s ", $i}' <<<"$l" | sed 's/ $//')"
        md_append "| ${port} | ${state} | ${service} | ${version} |"
    done < <(grep -E '^[0-9]+/[0-9a-z]+[[:space:]]+open([[:space:]]|\|)' "$ENUM_TXT")
else
    md_append "- Phase 2 (enumeration) **not performed** for this target."
fi

# ---------------------------------------------------------------
# Section 5 - Services and Versions
# ---------------------------------------------------------------

md_append ""
md_append "## 5. Services and Versions"
md_append ""
if [[ -n "$ENUM_TXT" ]]; then
    md_append "(Identified by Nmap service/version detection; source: $ENUM_TXT)"
    md_append ""
    while IFS= read -r l; do
        md_append "- $l"
    done < <(grep -E '^[0-9]+/[0-9a-z]+[[:space:]]+open([[:space:]]|\|)' "$ENUM_TXT")
else
    md_append "- No enumeration data."
fi

# ---------------------------------------------------------------
# Section 6 - Vulnerability Research
# ---------------------------------------------------------------

md_append ""
md_append "## 6. Vulnerability Research"
md_append ""
VULN_STATUS="not-performed"
if [[ -n "$VULN_RESEARCH_DIR" ]]; then
    VULN_STATUS="$(grep -E '^status=' "$VULN_RESEARCH_DIR/status.txt" | cut -d= -f2 | head -n1 || true)"
    md_append "- Source: $VULN_RESEARCH_DIR"
    md_append "- Status: **$VULN_STATUS**"
    if [[ -f "$VULN_RESEARCH_DIR/summary.txt" ]]; then
        md_append ""
        md_append "Summary:"
        md_append '```'
        while IFS= read -r l; do md_append "$l"; done < "$VULN_RESEARCH_DIR/summary.txt"
        md_append '```'
    fi
else
    md_append "- Phase 3 (SearchSploit research) **not performed**."
fi

# ---------------------------------------------------------------
# Section 7 - Correlated Findings
# ---------------------------------------------------------------

md_append ""
md_append "## 7. Correlated Findings"
md_append ""
md_append "> Correlation and confidence are produced by this tool's deterministic rules. "
md_append "> Severity is a categorical tool assessment (high/medium/low), **not an official CVSS score**. "
md_append "> No CVE/CVSS data is fabricated."
md_append ""
if [[ -n "$CORRELATION_DIR" && -f "$CORRELATION_DIR/correlated_findings.tsv" ]]; then
    md_append "| Port | Service | Product | Version | Confidence | Severity | Exploit title | EDB |"
    md_append "|---|---|---|---|---|---|---|---|"
    while IFS=$'\t' read -r t port proto service product ver title edb path cve plat type q conf sev sevsrc reason; do
        md_append "| ${port} | ${service} | ${product} | ${ver} | ${conf} | ${sev} | ${title} | ${edb} |"
    done < <(tail -n +2 "$CORRELATION_DIR/correlated_findings.tsv")
else
    md_append "- No correlated findings available (Phase 3/4 not completed or no matches)."
fi

# ---------------------------------------------------------------
# Section 8 - Exploit Candidates
# ---------------------------------------------------------------

md_append ""
md_append "## 8. Exploit Candidates"
md_append ""
md_append "> Candidates are *not* confirmed exploitable. They are correlations between "
md_append "> SearchSploit index entries and detected services; severity/confidence are tool assessments."
md_append ""
if [[ -n "$CORRELATION_DIR" && -f "$CORRELATION_DIR/correlated_findings.tsv" ]]; then
    FIND_IDX=0
    while IFS=$'\t' read -r t port proto service product ver title edb path cve plat type q conf sev sevsrc reason; do
        FIND_IDX=$((FIND_IDX + 1))
        md_append "### Candidate $FIND_IDX"
        md_append ""
        md_append "- **Port/Protocol:** ${port}/${proto}"
        md_append "- **Service/Product:** ${service} ${product} ${ver}"
        md_append "- **Exploit title (SearchSploit):** ${title}"
        md_append "- **EDB-ID:** ${edb}"
        md_append "- **Path:** ${path}"
        md_append "- **CVE (as indexed):** ${cve:-none}"
        md_append "- **Confidence:** ${conf} (${reason})"
        md_append "- **Severity:** ${sev} (tool assessment)"
        md_append ""
    done < <(tail -n +2 "$CORRELATION_DIR/correlated_findings.tsv")
else
    md_append "- No exploit candidates to report."
fi

# ---------------------------------------------------------------
# Section 9 - Exploitation Results
# ---------------------------------------------------------------

md_append ""
md_append "## 9. Exploitation Results"
md_append ""
md_append "> Exploitation is strictly limited to the authorized Metasploitable 2 lab target."
md_append ""
if [[ -n "$EXPLOIT_DIR" ]]; then
    md_append "- Source: $EXPLOIT_DIR"
    if [[ -f "$EXPLOIT_DIR/result.txt" ]]; then
        while IFS= read -r l; do
            [[ "$l" =~ ^(target|timestamp|selected_module|selected_payload|session_status|session_type|session_id|msfconsole_exit)= ]] && md_append "- $l"
        done < "$EXPLOIT_DIR/result.txt"
    fi
    md_append ""
    md_append "**Confirmed session:** $([ "$SESSION_STATUS" = session-created ] && echo yes || echo no)"
    if [[ -f "$EXPLOIT_DIR/exploit_output.txt" ]]; then
        md_append ""
        md_append "- Raw Metasploit output preserved at: $EXPLOIT_DIR/exploit_output.txt"
    fi
else
    md_append "- Phase 5 (exploitation) **not performed**."
fi

# ---------------------------------------------------------------
# Section 10 - Evidence
# ---------------------------------------------------------------

md_append ""
md_append "## 10. Evidence"
md_append ""
if [[ -n "$EVIDENCE_DIR" ]]; then
    md_append "- Source: $EVIDENCE_DIR"
    if [[ -f "$EVIDENCE_DIR/metadata.txt" ]]; then
        md_append ""
        md_append '```'
        while IFS= read -r l; do md_append "$l"; done < "$EVIDENCE_DIR/metadata.txt"
        md_append '```'
    fi
    md_append ""
    md_append "- Artifacts:"
    for f in "$EVIDENCE_DIR"/*; do
        [[ -f "$f" ]] && md_append "    - $(basename "$f")"
    done
else
    md_append "- Phase 6 (evidence) **not performed**."
fi

# ---------------------------------------------------------------
# Section 11 - Limitations
# ---------------------------------------------------------------

md_append ""
md_append "## 11. Limitations"
md_append ""
md_append "- This tool is designed for **authorized** Metasploitable 2 lab environments only."
md_append "- SearchSploit results are candidate correlations; they are not proof of exploitability."
md_append "- Severity values are categorical tool assessments, not official CVSS scores."
md_append "- No CVE, CVSS, or exploit ID is fabricated; only indexed data is reported."
if [[ "$VULN_STATUS" == "dependency-missing" ]] || [[ -z "$VULN_RESEARCH_DIR" ]]; then
    md_append "- Vulnerability research (SearchSploit) was **unavailable** - findings in section 6 are incomplete."
fi
if [[ -z "$EXPLOIT_DIR" ]] || [[ "$SESSION_STATUS" == "no-session" ]]; then
    md_append "- Exploitation did not succeed or was not run - target exploitability is unconfirmed."
fi

# ---------------------------------------------------------------
# Section 12 - Recommendations
# ---------------------------------------------------------------

md_append ""
md_append "## 12. Recommendations"
md_append ""
md_append "- The purpose of this lab is **learning**: use findings to understand how
   vulnerable service configurations are identified and (in-lab) exploited."
md_append "- For any in-scope confirmed finding, remediate the vulnerable service and re-run
   the assessment to confirm the finding no longer appears."
md_append "- Keep Metasploitable 2 isolated from production networks (Host-Only/Bridged lab network)."
md_append "- Validate every exploit candidate through the explicit-approval workflow before execution."

md_append ""
md_append "---"
md_append ""
md_append "*Generated by the security-assessment tool. Report content is derived from the tool's "
md_append "actual artifacts; any phase marked 'not performed' was not executed for this target.*"

printf '%s' "$MD" > "$MD_FILE"

# ---------------------------------------------------------------
# HTML rendering (best-effort, stdlib python only)
# ---------------------------------------------------------------

HTML_STATUS="skipped"
if [[ "$REPORT_FORMAT" == *html* ]] && sat_require python3; then
    if python3 - "$MD_FILE" "$HTML_FILE" <<'PY'
import html
import re
import sys

src, dst = sys.argv[1:3]
with open(src, 'r', encoding='utf-8') as fh:
    lines = fh.read().splitlines()

out = []
in_fence = False
for line in lines:
    if line.strip().startswith('```'):
        in_fence = not in_fence
        out.append('<pre>')
        continue
    if in_fence:
        out.append(html.escape(line))
        continue
    stripped = line.strip()
    m = re.match(r'^(#{1,6})\s+(.*)$', line)
    if m:
        level = len(m.group(1))
        out.append("<h%d>%s</h%d>" % (level, html.escape(m.group(2)), level))
        continue
    if stripped.startswith('- '):
        out.append("<ul><li>%s</li></ul>" % html.escape(stripped[2:]))
        continue
    m = re.match(r'^\|(.+)\|$', line)
    if m and line.startswith('|'):
        cells = [c.strip() for c in line.strip('|').split('|')]
        if all(re.match(r'^--+$', c or '-') for c in cells):
            continue
        out.append('<tr>' + ''.join('<td>%s</td>' % html.escape(c) for c in cells) + '</tr>')
        continue
    if line.strip() == '':
        out.append('')
    else:
        out.append('<p>%s</p>' % html.escape(line))

body = '\n'.join(out)
body = re.sub(r'</ul><ul>', '', body)
page = "<html><head><meta charset='utf-8'><title>%s</title></head><body>%s</body></html>" % (
    html.escape('Security Assessment Report'), body)
with open(dst, 'w', encoding='utf-8') as fh:
    fh.write(page)
PY
    then
        HTML_STATUS="generated"
    else
        HTML_STATUS="error"
    fi
fi

{
    echo "status=completed"
    echo "timestamp=$TIMESTAMP"
    echo "target=$TARGET"
    echo "report_md=$(basename "$MD_FILE")"
    echo "report_html=$(basename "$HTML_FILE")"
    echo "host_state=$HOST_STATE"
    echo "open_ports=$OPEN_COUNT"
    echo "vuln_status=$VULN_STATUS"
    echo "session_status=$SESSION_STATUS"
} > "$REPORT_DIR/${SAFE_TARGET}_${TIMESTAMP}.status.txt"

echo "========================================"
echo "              REPORT"
echo "========================================"
echo
echo "[+] Report generated:"
echo "    $MD_FILE"
if [[ "$HTML_STATUS" == "generated" ]]; then
    echo "    $HTML_FILE"
fi
echo
echo "[+] $REPORT_TITLE for $TARGET"
echo "[-] Report status: completed (host=$HOST_STATE, open_ports=$OPEN_COUNT, findings=$FINDINGS_TOTAL, session=$SESSION_STATUS)"
echo

exit "$EXIT_OK"