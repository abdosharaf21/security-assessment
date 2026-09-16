#!/usr/bin/env bash
#
# Phase 4 - Finding Correlation / Risk
#
# Usage:
#   ./modules/correlation.sh <target> [vulnerability_dir]
#
# Correlates Phase 3 SearchSploit candidates against the actual detected
# service product/version. A candidate only becomes a finding when the
# exploit title mentions the detected product (and, when possible, the
# detected version).
#
# Confidence (deterministic, evidence-based):
#   high   - product matches AND detected version appears in the title
#   medium - product matches AND title version shares major.minor
#   low    - product matches, no version evidence in the title
#
# Severity is a transparent CANDIDATE-selection of the tool, never an
# official CVSS value (no CVSS data is fabricated).
#
# Exit codes:
#   0  correlation completed (findings may be zero - see summary.txt)
#   1  usage/technical error
#   2  expected input files from Phase 3 are missing/empty

set -uo pipefail

COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)"
# shellcheck source=lib/common.sh
source "$COMMON_DIR/common.sh"

EXIT_OK=0
EXIT_ERROR=1
EXIT_NO_DATA=2

usage() {
    echo "Usage: $0 <target> [vulnerability_dir]"
    echo "Example: $0 192.168.56.101"
    echo "         $0 192.168.56.101 output/vulnerabilities/192.168.56.101_20260101_100000"
}

TARGET="${1:-}"
if [[ -z "$TARGET" ]] || ! sat_validate_target "$TARGET"; then
    usage
    exit "$EXIT_ERROR"
fi

sat_load_config || exit "$EXIT_ERROR"
sat_apply_defaults

if ! sat_require_python3; then
    exit "$EXIT_ERROR"
fi

SAFE_TARGET="$(sat_safe_name "$TARGET")"
VULN_DIR="${2:-}"
if [[ -z "$VULN_DIR" ]]; then
    VULN_DIR="$(sat_latest_dir_with "$OUTPUT_VULN" "$SAFE_TARGET" "services.tsv")"
fi

if [[ -z "$VULN_DIR" || ! -d "$VULN_DIR" ]]; then
    echo "[-] No vulnerability-research output found for target '$TARGET'." >&2
    echo "    Run Phase 3 first: ./modules/vulnerability.sh $TARGET" >&2
    exit "$EXIT_NO_DATA"
fi

if [[ ! -f "$VULN_DIR/services.tsv" || ! -f "$VULN_DIR/exploitdb_candidates.tsv" ]]; then
    echo "[-] Expected Phase 3 files not found in: $VULN_DIR" >&2
    exit "$EXIT_NO_DATA"
fi

# A dependency-missing Phase 3 cannot be correlated.
if [[ -f "$VULN_DIR/status.txt" ]] && grep -q "status=dependency-missing" "$VULN_DIR/status.txt"; then
    echo "[-] Phase 3 did not complete (dependency missing) - nothing to correlate." >&2
    exit "$EXIT_NO_DATA"
fi

TIMESTAMP="$(sat_timestamp)"
DIR="$OUTPUT_VULN/${SAFE_TARGET}_${TIMESTAMP}"
mkdir -p "$DIR"

echo "========================================"
echo "       FINDING CORRELATION / RISK"
echo "========================================"
echo
echo "[*] Target:              $TARGET"
echo "[*] Vulnerability dir:   $VULN_DIR"
echo "[*] Output dir:          $DIR"
echo

python3 - "$TARGET" "$VULN_DIR/services.tsv" "$VULN_DIR/exploitdb_candidates.tsv" \
    "$DIR/correlated_findings.tsv" "$DIR/findings.json" <<'PY'
import csv
import json
import os
import re
import sys

target, services_path, cands_path, out_tsv, out_json = sys.argv[1:6]

# -------------------------------------------------------------
# deterministic correlation helpers
# -------------------------------------------------------------

def words(text):
    return set(re.findall(r'[a-z0-9][a-z0-9+._-]*', text.lower()))

def version_key(text):
    m = re.search(r'[0-9]+(\.[0-9]+){0,3}', text or '')
    return m.group(0) if m else ''

def major_minor(text):
    m = re.search(r'[0-9]+(\.[0-9]+)', text or '')
    return m.group(1) if m else ''

def correlate(service, cand):
    product = (service.get('product') or '').strip()
    version = (service.get('version') or '').strip()
    title = (cand.get('title') or '').strip()
    typ = (cand.get('type') or '').strip()

    if not product or not title:
        return None

    title_text = title.lower()
    title_words = words(title_text)
    product_words = words(product)

    if not product_words:
        return None

    matches_product = any(w in title_words for w in product_words)

    if not matches_product:
        return None

    # version evidence from the title
    exact = False
    range_match = False
    if version:
        vk = version_key(version)
        if vk and vk.lower() in title_text:
            exact = True
        mm = major_minor(version)
        if (not exact) and mm and mm in title_text:
            range_match = True

    if exact:
        confidence = 'high'
    elif range_match:
        confidence = 'medium'
    else:
        confidence = 'low'

    # severity: transparent categorical assessment by this tool
    if confidence == 'high' and typ.lower() in ('remote', 'webapps'):
        severity = 'high'
    elif confidence in ('high', 'medium'):
        severity = 'medium'
    else:
        severity = 'low'

    if exact:
        reason = "product '%s' matches exploit title and detected version '%s' is present in the title" % (product, version)
    elif range_match:
        reason = "product '%s' matches exploit title; title version range is consistent with detected version '%s'" % (product, version)
    else:
        reason = "product '%s' matches exploit title but no version evidence was found in the title" % product

    return {
        'target': target,
        'port': service.get('port') or cand.get('port') or '',
        'protocol': service.get('protocol') or '',
        'service': service.get('service') or '',
        'product': product,
        'detected_version': version,
        'exploit_title': title,
        'edb_id': cand.get('edb_id') or '',
        'exploit_path': cand.get('path') or '',
        'cve': cand.get('cve') or '',
        'platform': cand.get('platform') or '',
        'type': typ,
        'search_query': cand.get('query') or '',
        'confidence': confidence,
        'severity': severity,
        'severity_source': 'tool-assessment (categorical, not CVSS)',
        'match_reason': reason,
    }

# -------------------------------------------------------------
# load input
# -------------------------------------------------------------

services = []
with open(services_path, 'r', encoding='utf-8') as fh:
    for row in csv.DictReader(fh, delimiter='\t'):
        services.append(row)

candidates = []
with open(cands_path, 'r', encoding='utf-8') as fh:
    for row in csv.DictReader(fh, delimiter='\t'):
        if row.get('edb_id'):
            candidates.append(row)

by_index = {s.get('index'): s for s in services}

findings = []
dropped_no_product = 0
for cand in candidates:
    svc = by_index.get(cand.get('service_index') or '')
    if svc is None:
        dropped_no_product += 1
        continue
    f = correlate(svc, cand)
    if f is None:
        dropped_no_product += 1
        continue
    findings.append(f)

order = {'high': 0, 'medium': 1, 'low': 2}
findings.sort(key=lambda f: (order.get(f['severity'], 9), f['port']))

with open(out_tsv, 'w', encoding='utf-8') as fh:
    header = ['target', 'port', 'protocol', 'service', 'product', 'detected_version',
              'exploit_title', 'edb_id', 'exploit_path', 'cve', 'platform', 'type',
              'search_query', 'confidence', 'severity', 'severity_source', 'match_reason']
    w = csv.writer(fh, delimiter='\t', lineterminator='\n')
    w.writerow(header)
    for f in findings:
        w.writerow([f[h] for h in header])

payload = {
    'tool': 'security-assessment',
    'phase': 4,
    'phase_label': 'finding-correlation',
    'target': target,
    'timestamp': '',
    'source': os.path.basename(os.path.dirname(services_path)) or '',
    'services_considered': len(services),
    'candidates_considered': len(candidates),
    'dropped_no_product_match': dropped_no_product,
    'findings': findings,
    'methodology': {
        'confidence': {
            'high': 'product matches AND detected version appears in exploit title',
            'medium': 'product matches AND title version shares major.minor with detected version',
            'low': 'product matches, no version evidence in title',
        },
        'severity': 'tool-assessment categorical (high/medium/low), not an official CVSS score',
    },
}
with open(out_json, 'w', encoding='utf-8') as fh:
    json.dump(payload, fh, indent=2)

# human readable
with open(os.path.join(os.path.dirname(out_tsv), 'findings.txt'), 'w', encoding='utf-8') as fh:
    fh.write("Correlated findings for %s\n" % target)
    fh.write("Fields rely on this tool's deterministic correlation; severity is a categorical tool assessment, not CVSS.\n\n")
    for i, f in enumerate(findings, start=1):
        fh.write("[%d] %s %s/%s - %s %s\n" % (
            i, f['severity'].upper(), f['port'], f['protocol'],
            f['product'], f['detected_version']))
        fh.write("    Title: %s\n" % f['exploit_title'])
        fh.write("    EDB-ID: %s | Path: %s | Type: %s\n" % (f['edb_id'], f['exploit_path'], f['type']))
        fh.write("    Confidence: %s | %s\n" % (f['confidence'], f['match_reason']))
        fh.write("\n")
    fh.write("Findings total: %d\n" % len(findings))
PY

if [[ ! -f "$DIR/correlated_findings.tsv" ]]; then
    echo "[-] Correlation script did not produce output." >&2
    exit "$EXIT_ERROR"
fi

FINDINGS_COUNT="$(($(wc -l < "$DIR/correlated_findings.tsv") - 1))"
HIGH_COUNT="$(awk -F'\t' 'NR>1 && $14=="high" && $15=="high" {c++} END{print c+0}' "$DIR/correlated_findings.tsv" || true)"
MEDIUM_COUNT="$(awk -F'\t' 'NR>1 && $15=="medium" {c++} END{print c+0}' "$DIR/correlated_findings.tsv" || true)"
LOW_COUNT="$(awk -F'\t' 'NR>1 && $15=="low" {c++} END{print c+0}' "$DIR/correlated_findings.tsv" || true)"

{
    echo "status=completed"
    echo "timestamp=$TIMESTAMP"
    echo "target=$TARGET"
    echo "source_dir=$VULN_DIR"
    echo "findings=$FINDINGS_COUNT"
    echo "findings_high=$HIGH_COUNT"
    echo "findings_medium=$MEDIUM_COUNT"
    echo "findings_low=$LOW_COUNT"
} > "$DIR/status.txt"

{
    echo "Phase 4 - Finding Correlation / Risk"
    echo "Target: $TARGET"
    echo "Timestamp: $TIMESTAMP"
    echo "Source: $VULN_DIR"
    echo
    echo "Correlated findings: $FINDINGS_COUNT"
    echo "  high   (remote/webapp exploit + version match): $HIGH_COUNT"
    echo "  medium (version range evidence):                $MEDIUM_COUNT"
    echo "  low    (product only):                          $LOW_COUNT"
    echo
    echo "Severity values are the tool's categorical assessment, not CVSS."
    echo "No CVE/CVSS is fabricated."
    echo
    echo "Files:"
    echo "  correlated_findings.tsv - machine readable findings"
    echo "  findings.json           - merged phase 4 results"
    echo "  findings.txt            - human readable findings"
    echo "  status.txt              - phase status"
} > "$DIR/summary.txt"

echo "------------------------------------------------------------"
cat "$DIR/summary.txt"
echo "------------------------------------------------------------"
echo
echo "[+] Phase 4 completed."
echo "[-] Output directory: $DIR"

[[ "$FINDINGS_COUNT" -gt 0 ]] && exit "$EXIT_OK"
echo "[!] No correlated findings - this is a valid, evidence-based result."
exit "$EXIT_OK"