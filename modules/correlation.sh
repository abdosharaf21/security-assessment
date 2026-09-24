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
# Confidence (deterministic, evidence-based) - see match_type for the model:
#   EXACT_VERSION_MATCH            - detected concrete version equals the candidate's
#   VERSION_RANGE_MATCH            - detected version falls inside the title's range
#   STRONG_PRODUCT_SERVICE_MATCH   - product family + specific component both match
#   PRODUCT_MATCH_ONLY             - product matches, no comparable version in title
#   VERSION_UNKNOWN                - detected version is generic/unknown (e.g. 3.X - 4.X)
#   VERSION_CONFLICT               - detected version contradicts the title statement
#   VENDOR_ONLY_MATCH              - only a generic vendor word matched (e.g. Apache)
#
# Each finding carries match_type / risk_category / evidence_confidence.
# A SearchSploit candidate is a CANDIDATE, never a confirmed vulnerability.
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
# Evidence model (deterministic, this tool's own categorical rules)
# -------------------------------------------------------------
# A candidate is never a confirmed vulnerability; it is a correlated
# candidate/evidence. Three fields are produced for every finding:
#   match_type          - HOW the candidate relates to the detected service
#   evidence_confidence - strength of the supporting evidence
#   risk_category       - categorical severity (never CVSS)
#
# match_type, strongest first:
#   EXACT_VERSION_MATCH           detected concrete version equals candidate version
#   VERSION_RANGE_MATCH           detected concrete version falls inside the title's
#                                 stated affected range (e.g. "3.0.20 < 3.0.25rc3")
#   STRONG_PRODUCT_SERVICE_MATCH  product family AND the specific component token
#                                 both appear in the title (no comparable version)
#   PRODUCT_MATCH_ONLY            product family matches, detected version concrete
#                                 but the title states no usable version
#   VERSION_UNKNOWN               detected version is generic/unknown ("3.X - 4.X",
#                                 "unknown", empty) so no version comparison possible
#   VERSION_CONFLICT              detected concrete version contradicts the version
#                                 stated in the title -> low-confidence reference only
#   VENDOR_ONLY_MATCH             only a generic vendor word (e.g. "apache") is
#                                 shared; the specific product was NOT identified
# -------------------------------------------------------------

GENERIC_VENDORS = {
    'apache', 'microsoft', 'oracle', 'sun', 'ibm', 'redhat', 'dell', 'hp',
    'sap', 'vmware', 'cisco', 'google', 'amazon', 'apple', 'adobe', 'mozilla',
    'symantec', 'trendmicro', 'kaspersky', 'juniper', 'citrix', 'netscape',
    'novell', 'huawei', 'suse', 'canonical', 'debian', 'akamai', 'cloudflare',
}

MATCH_RANK = {
    'EXACT_VERSION_MATCH': 0,
    'VERSION_RANGE_MATCH': 1,
    'STRONG_PRODUCT_SERVICE_MATCH': 2,
    'PRODUCT_MATCH_ONLY': 3,
    'VERSION_UNKNOWN': 4,
    'VERSION_CONFLICT': 5,
    'VENDOR_ONLY_MATCH': 6,
}

CONF_RANK = {'high': 0, 'medium': 1, 'low': 2}

# -------------------------------------------------------------
# deterministic version helpers
# -------------------------------------------------------------

def words(text):
    return set(re.findall(r'[a-z0-9][a-z0-9+._-]*', (text or '').lower()))

def ordered_tokens(text):
    # product-string tokens in their original order (lowercased)
    return re.findall(r'[a-z0-9][a-z0-9+._-]*', (text or '').lower())

def version_tokens(text):
    # version-shaped tokens, e.g. 3.0.20, 3.0.25rc3, 2.2.x
    return [m.group(0) for m in re.finditer(
        r'\b[0-9]+(?:\.[0-9xX]+)*(?:[a-z0-9]*)\b', (text or '').lower())]

def vtuple(tok):
    # 3.0.25rc3 -> (3,0,25); 2.2.x -> (2,2,None); 1.2x -> (1,2,None)
    # A dotted segment that is not fully numeric (wildcard x/X, or a suffix
    # merged into the segment like the 'x' in 1.2x) is treated as unknown,
    # never int()'d, so malformed/partial evidence cannot raise.
    m = re.match(r'([0-9]+(?:\.[0-9xX]+)*)', tok or '')
    if not m:
        return ()
    parts = []
    for p in m.group(1).split('.'):
        parts.append(int(p) if p.isdigit() else None)
    return tuple(parts)

def concrete(tup):
    return bool(tup) and all(p is not None for p in tup)

def pad(tup, n):
    t = list(tup)
    if len(t) < n:
        t.extend([None] * (n - len(t)))
    return tuple(t)

def level_cmp(a, b):
    if a is None or b is None:
        return 0
    return (a > b) - (a < b)

def tup_cmp(a, b):
    n = max(len(a), len(b), 1)
    for x, y in zip(pad(a, n), pad(b, n)):
        r = level_cmp(x, y)
        if r:
            return r
    return 0

def parse_detected(ver):
    # Returns ('concrete', tuple) or ('generic', tuple) - generic when the
    # reported version is empty/unknown or a wildcard band such as "3.X - 4.X".
    v = (ver or '').strip()
    if not v:
        return 'generic', ()
    low = v.lower()
    if low in ('unknown', 'not detected', 'n/a', '-', 'none', 'na'):
        return 'generic', ()
    toks = version_tokens(low)
    if not toks:
        return 'generic', ()
    t = vtuple(toks[0])
    if not concrete(t) or 'x' in low:
        return 'generic', t
    return 'concrete', t

def candidate_versions(title):
    # ('none', None, None) | ('single', t, None) | ('range', lo, hi)
    low = (title or '').lower()
    hits = list(re.finditer(r'\b[0-9]+(?:\.[0-9xX]+)*(?:[a-z0-9]*)\b', low))
    if not hits:
        return 'none', None, None
    if len(hits) >= 2:
        lo = vtuple(hits[0].group(0))
        hi = vtuple(hits[1].group(0))
        between = low[hits[0].end():hits[1].start()]
        if re.search(r'<\s*|<=|>=|>\s*|[-+]\s*|to\s+|through\s+|up\s+to\s+|until\s+|between\s+', between):
            return 'range', lo, hi
    return 'single', vtuple(hits[0].group(0)), None

def family_match(cand_tup, det_tup):
    # candidate tuple may carry wildcards (2.2.x matches any 2.2.*)
    n = max(len(cand_tup), len(det_tup))
    for x, y in zip(pad(list(cand_tup), n), pad(list(det_tup), n)):
        if x is None:
            continue
        if level_cmp(x, y) != 0:
            return False
    return True

def in_range(det_tup, lo, hi):
    return tup_cmp(det_tup, lo) >= 0 and tup_cmp(det_tup, hi) <= 0

def service_specific_token(product):
    toks = ordered_tokens(product)
    if not toks:
        return ''
    if len(toks) > 1 and toks[-1] not in GENERIC_VENDORS:
        return toks[-1]
    return toks[0]

# -------------------------------------------------------------
# correlation core
# -------------------------------------------------------------

def correlate(service, cand):
    product = (service.get('product') or '').strip()
    version = (service.get('version') or '').strip()
    title = (cand.get('title') or '').strip()
    typ = (cand.get('type') or '').strip()

    if not product or not title:
        return None

    title_words = words(title)
    product_tokens = words(product)
    if not product_tokens:
        return None

    shared = product_tokens & title_words
    if not shared:
        return None

    distinct = product_tokens.difference(GENERIC_VENDORS)
    prod_family = bool(distinct & title_words)
    vendor_only = not prod_family

    det_state, det_tup = parse_detected(version)
    mode, lo, hi = candidate_versions(title)
    service_specific = service_specific_token(product)
    service_specific_hit = bool(service_specific) and service_specific in title_words

    if vendor_only:
        match_type = 'VENDOR_ONLY_MATCH'
        confidence = 'low'
        reason = "only generic vendor word(s) shared (%s); candidate product '%s' was not specifically identified" % (
            ', '.join(sorted(shared)), product)
    elif mode == 'none':
        if det_state == 'generic':
            match_type = 'VERSION_UNKNOWN'
        else:
            match_type = 'PRODUCT_MATCH_ONLY'
        confidence = 'low'
        reason = "product '%s' matches exploit title but the title states no version" % product
    elif mode == 'single':
        if det_state == 'generic':
            match_type = 'VERSION_UNKNOWN'
            confidence = 'low'
            reason = "product '%s' matches exploit title but detected version '%s' is generic/unknown - not comparable" % (product, version)
        elif concrete(det_tup) and concrete(lo) and det_tup == lo:
            match_type = 'EXACT_VERSION_MATCH'
            confidence = 'high'
            reason = "detected version '%s' exactly matches the version ('%s') stated in the title" % (version, lo and '.'.join(str(p) for p in lo))
        elif concrete(det_tup) and concrete(lo) and family_match(lo, det_tup):
            match_type = 'VERSION_RANGE_MATCH'
            confidence = 'medium'
            reason = "detected version '%s' falls inside the version family ('%s') stated in the title" % (version, '.'.join(str(p) for p in lo))
        elif concrete(det_tup) and concrete(lo):
            match_type = 'VERSION_CONFLICT'
            confidence = 'low'
            reason = "detected version '%s' contradicts the version ('%s') stated in the title" % (version, '.'.join(str(p) for p in lo))
        else:
            match_type = 'VERSION_UNKNOWN'
            confidence = 'low'
            reason = "product '%s' matches exploit title but versions are not comparable" % product
    else:  # range
        if det_state == 'generic':
            match_type = 'VERSION_UNKNOWN'
            confidence = 'low'
            reason = "product '%s' matches exploit title but detected version '%s' is generic/unknown - range '%s .. %s' not verifiable" % (
                product, version, fmt_tup(lo), fmt_tup(hi))
        elif concrete(det_tup) and concrete(lo) and concrete(hi) and in_range(det_tup, lo, hi):
            match_type = 'VERSION_RANGE_MATCH'
            confidence = 'medium'
            reason = "detected version '%s' is inside the affected range '%s .. %s' stated in the title" % (
                version, fmt_tup(lo), fmt_tup(hi))
        elif concrete(det_tup) and concrete(lo) and concrete(hi):
            match_type = 'VERSION_CONFLICT'
            confidence = 'low'
            reason = "detected version '%s' is outside the affected range '%s .. %s' stated in the title" % (
                version, fmt_tup(lo), fmt_tup(hi))
        else:
            match_type = 'VERSION_UNKNOWN'
            confidence = 'low'
            reason = "product '%s' matches exploit title but versions are not comparable" % product

    # A product family match that also names the specific component/daemon
    # (e.g. 'smbd', 'httpd', 'jserv') is stronger than a bare product-only match.
    if match_type in ('PRODUCT_MATCH_ONLY', 'VERSION_UNKNOWN') and service_specific_hit:
        match_type = 'STRONG_PRODUCT_SERVICE_MATCH'
        confidence = 'medium'
        reason = "product '%s' matches the exploit title by its specific component '%s' (no comparable version evidence)" % (
            product, service_specific)

    # Severity remains a transparent categorical tool assessment, never CVSS.
    if confidence == 'high' and typ.lower() in ('remote', 'webapps'):
        severity = 'high'
    elif confidence in ('high', 'medium'):
        severity = 'medium'
    else:
        severity = 'low'

    if match_type == 'EXACT_VERSION_MATCH':
        version_evidence = "exact: detected '%s' == candidate '%s'" % (version, fmt_tup(lo))
    elif match_type == 'VERSION_RANGE_MATCH':
        version_evidence = "range: detected '%s' inside '%s .. %s'" % (version, fmt_tup(lo), fmt_tup(hi))
    elif match_type == 'VERSION_CONFLICT':
        version_evidence = "conflict: detected '%s' vs '%s'" % (version, fmt_tup(lo))
    elif det_state == 'generic':
        version_evidence = "unknown: detected version '%s' is generic/unknown" % version
    elif mode == 'none':
        version_evidence = "product-only: title states no version"
    else:
        version_evidence = "low: version evidence not comparable"

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
        'match_type': match_type,
        'risk_category': severity,
        'evidence_confidence': confidence,
        'version_evidence': version_evidence,
    }

def fmt_tup(t):
    if not t:
        return ''
    return '.'.join('x' if p is None else str(p) for p in t)

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
dropped_vendor_only = 0
for cand in candidates:
    svc = by_index.get(cand.get('service_index') or '')
    if svc is None:
        dropped_no_product += 1
        continue
    f = correlate(svc, cand)
    if f is None:
        dropped_no_product += 1
        continue
    if f['match_type'] == 'VENDOR_ONLY_MATCH':
        dropped_vendor_only += 1
    findings.append(f)

def port_num(p):
    return int(p) if str(p).isdigit() else 65535

def edb_num(e):
    return int(e) if str(e).isdigit() else 10 ** 9

# Deterministic ordering: strongest evidence first (expressible to the user),
# then categorical risk, then evidence confidence, then port / EDB-ID.
findings.sort(key=lambda f: (
    MATCH_RANK.get(f['match_type'], 9),
    CONF_RANK.get(f['risk_category'], 9),
    CONF_RANK.get(f['evidence_confidence'], 9),
    port_num(f['port']),
    edb_num(f['edb_id']),
    f['product'],
    f['exploit_title'],
))

with open(out_tsv, 'w', encoding='utf-8') as fh:
    header = ['target', 'port', 'protocol', 'service', 'product', 'detected_version',
              'exploit_title', 'edb_id', 'exploit_path', 'cve', 'platform', 'type',
              'search_query', 'confidence', 'severity', 'severity_source', 'match_reason',
              'match_type', 'risk_category', 'evidence_confidence', 'version_evidence']
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
    'kept_vendor_only_reference': dropped_vendor_only,
    'findings': findings,
    'methodology': {
        'match_type': {
            'EXACT_VERSION_MATCH': 'detected concrete version equals the candidate version',
            'VERSION_RANGE_MATCH': 'detected concrete version falls inside the affected range stated in the title',
            'STRONG_PRODUCT_SERVICE_MATCH': 'product family and its specific component both match; no comparable version evidence',
            'PRODUCT_MATCH_ONLY': 'product family matches; detected version concrete but title states no usable version',
            'VERSION_UNKNOWN': 'detected version is generic/unknown (e.g. "3.X - 4.X"); no version comparison possible',
            'VERSION_CONFLICT': 'detected concrete version contradicts the title statement; kept as a low-confidence reference',
            'VENDOR_ONLY_MATCH': 'only a generic vendor word is shared (e.g. "Apache"); the specific product was not identified',
        },
        'evidence_confidence': {
            'high': 'EXACT_VERSION_MATCH',
            'medium': 'VERSION_RANGE_MATCH / STRONG_PRODUCT_SERVICE_MATCH',
            'low': 'PRODUCT_MATCH_ONLY / VERSION_UNKNOWN / VERSION_CONFLICT / VENDOR_ONLY_MATCH',
        },
        'risk_category': 'tool-assessment categorical (high/medium/low), not an official CVSS score; no CVE/CVSS is fabricated',
    },
}
with open(out_json, 'w', encoding='utf-8') as fh:
    json.dump(payload, fh, indent=2)

# human readable
with open(os.path.join(os.path.dirname(out_tsv), 'findings.txt'), 'w', encoding='utf-8') as fh:
    fh.write("Correlated findings for %s\n" % target)
    fh.write("Fields rely on this tool's deterministic correlation; severity is a categorical tool assessment, not CVSS.\n")
    fh.write("match_type: exact | range | strong product/service | product-only | version-unknown | version-conflict | vendor-only\n\n")
    for i, f in enumerate(findings, start=1):
        fh.write("[%d] %s %s/%s - %s %s\n" % (
            i, f['severity'].upper(), f['port'], f['protocol'],
            f['product'], f['detected_version']))
        fh.write("    Title: %s\n" % f['exploit_title'])
        fh.write("    EDB-ID: %s | Path: %s | Type: %s\n" % (f['edb_id'], f['exploit_path'], f['type']))
        fh.write("    Match: %s | Risk: %s | Confidence: %s\n" % (
            f['match_type'], f['risk_category'], f['evidence_confidence']))
        fh.write("    Version evidence: %s\n" % f['version_evidence'])
        fh.write("    %s\n" % f['match_reason'])
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
    echo "  high   (exact match + remote/webapp exploit):         $HIGH_COUNT"
    echo "  medium (range / strong product-service evidence):     $MEDIUM_COUNT"
    echo "  low    (product-only / unknown / conflict / vendor):  $LOW_COUNT"
    echo
    echo "Severity values are the tool's categorical assessment, not CVSS."
    echo "No CVE/CVSS is fabricated."
    echo
    echo "match_type: exact-version | version-range | strong-product-service |"
    echo "            product-only | version-unknown | version-conflict | vendor-only"
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