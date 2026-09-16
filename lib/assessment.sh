#!/usr/bin/env bash
#
# Assessment Manager - IDs, run isolation, manifest state, resume planning.
# Source this file after lib/common.sh, do not execute it directly.
#
# Provides:
#   sat_assessment_id_new
#   sat_assessment_create
#   sat_assessment_load
#   sat_assessment_set_outputs
#   sat_assessment_manifest_get / sat_assessment_manifest_set
#   sat_assessment_add_completed / sat_assessment_add_failed
#   sat_assessment_is_completed
#   sat_assessment_phase_done
#   sat_assessment_build_plan
#
# Layout:
#   output/assessments/<assessment_id>/
#     manifest.json
#     discovery/ enumeration/ vulnerabilities/ correlation/
#     exploitation/ evidence/ report/
#
# Manifest (JSON, plain metadata only - never secrets):
#   assessment_id, target, started_at, updated_at, status,
#   current_phase, completed_phases[], failed_phases[]

if [[ -n "${SAT_ASSESSMENT_LOADED:-}" ]]; then
    return 0
fi
SAT_ASSESSMENT_LOADED=1

ASSESSMENTS_ROOT="${ASSESSMENTS_ROOT:-$OUTPUT_ROOT/assessments}"

# Phases that form the automatic non-exploit assessment pipeline.
# exploitation is NEVER part of this list (explicit approval only) and
# evidence only runs after exploitation results actually exist.
SAT_PIPELINE=(discovery enumeration vulnerabilities correlation evidence report)

sat_assessment_module_name() {
    case "$1" in
        vulnerabilities) printf 'vulnerability.sh' ;;
        *) printf '%s.sh' "$1" ;;
    esac
}

# ---------------------------------------------------------------
# IDs / lifecycle
# ---------------------------------------------------------------

# sat_assessment_id_new -> prints a free nanosecond-based assessment id.
sat_assessment_id_new() {
    local base="$ASSESSMENTS_ROOT" id ts n=0
    while true; do
        ts="$(date '+%Y%m%d_%H%M%S%N' 2>/dev/null || date '+%Y%m%d_%H%M%S')"
        id="assessment_${ts}"
        if [[ ! -e "$base/$id" ]]; then
            printf '%s' "$id"
            return 0
        fi
        n=$((n + 1))
        if (( n > 50 )); then
            id="assessment_$(date '+%Y%m%d_%H%M%S%N')_${n}"
            printf '%s' "$id"
            return 0
        fi
    done
}

# sat_assessment_create <target> -> id. Creates dirs + manifest, exports
# SAT_ASSESSMENT_ID / ASSESSMENT_DIR / ASSESSMENT_TARGET, redirects outputs.
sat_assessment_create() {
    local target="$1" id dir started now p
    if ! sat_validate_target "$target"; then
        echo "[-] Invalid target: $target" >&2
        return 1
    fi
    started="$(date '+%Y-%m-%dT%H:%M:%S%z')"
    id="$(sat_assessment_id_new)" || return 1
    dir="$ASSESSMENTS_ROOT/$id"

    for p in discovery enumeration vulnerabilities correlation exploitation evidence report; do
        if ! mkdir -p "$dir/$p"; then
            echo "[-] Could not create assessment directory: $dir/$p" >&2
            return 1
        fi
    done

    python3 - "$dir/manifest.json" "$id" "$target" "$started" <<'PY' || return 1
import json
import sys

path, aid, target, started = sys.argv[1:5]
manifest = {
    "assessment_id": aid,
    "target": target,
    "started_at": started,
    "updated_at": started,
    "status": "in_progress",
    "current_phase": "",
    "completed_phases": [],
    "failed_phases": [],
}
with open(path, "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PY

    SAT_ASSESSMENT_ID="$id"
    ASSESSMENT_DIR="$dir"
    ASSESSMENT_TARGET="$target"
    sat_assessment_set_outputs "$dir"
    return 0
}

# sat_assessment_exists <id> -> 0 when the assessment directory exists.
sat_assessment_exists() {
    [[ -d "$ASSESSMENTS_ROOT/$1" ]]
}

# sat_assessment_ensure <id> -> creates a minimal, scope-based assessment
# shell (same layout as sat_assessment_create but with no single target)
# when it does not already exist. Returns 1 on invalid ids.
sat_assessment_ensure() {
    local id="${1:-}" dir started p
    [[ "$id" == assessment_* ]] || {
        echo "[-] Invalid assessment id: '$id' (must start with 'assessment_')." >&2
        return 1
    }
    if [[ -d "$ASSESSMENTS_ROOT/$id" ]]; then
        return 0
    fi
    dir="$ASSESSMENTS_ROOT/$id"
    if ! mkdir -p "$dir/scopes"; then
        echo "[-] Could not create assessment directory: $dir" >&2
        return 1
    fi
    started="$(date '+%Y-%m-%dT%H:%M:%S%z')"
    python3 - "$dir/manifest.json" "$id" "$started" <<'PY' || return 1
import json
import sys

path, aid, started = sys.argv[1:4]
manifest = {
    "assessment_id": aid,
    "target": "",
    "scope_based": True,
    "started_at": started,
    "updated_at": started,
    "status": "in_progress",
    "current_phase": "",
    "completed_phases": [],
    "failed_phases": [],
}
with open(path, "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PY
    for p in discovery enumeration vulnerabilities correlation exploitation evidence report; do
        mkdir -p "$dir/$p" || true
    done
    echo "[+] Assessment created: $id"
    return 0
}

# sat_assessment_load <id> -> exports ASSESSMENT_DIR/ASSESSMENT_TARGET and
# returns 0 only when the directory and a well-formed matching manifest
# exist. Never fabricates state for missing/corrupt artifacts.
sat_assessment_load() {
    local id="$1"
    local dir="$ASSESSMENTS_ROOT/$id"
    if [[ ! -d "$dir" ]]; then
        echo "[-] Assessment not found: $id" >&2
        return 1
    fi
    if [[ ! -f "$dir/manifest.json" ]]; then
        echo "[-] Assessment '$id' has no manifest.json (missing state)." >&2
        return 1
    fi
    if ! python3 - "$dir/manifest.json" "$id" "$dir" 2>/dev/null <<'PY'; then
import json
import os
import sys

path, want, adir = sys.argv[1:4]
try:
    with open(path) as f:
        m = json.load(f)
except Exception:
    sys.exit(1)
if not isinstance(m, dict):
    sys.exit(1)
if m.get("assessment_id") != want:
    sys.exit(1)
# A scope-based assessment may have no single "target" (targets live in
# its scopes). Plain single-target assessments must keep a target.
if not m.get("target") and not os.path.isdir(os.path.join(adir, "scopes")):
    sys.exit(1)
PY
        echo "[-] Assessment '$id' has a missing or corrupt manifest (refusing to fabricate state)." >&2
        return 1
    fi

    SAT_ASSESSMENT_ID="$id"
    ASSESSMENT_DIR="$dir"
    ASSESSMENT_TARGET="$(sat_assessment_manifest_get "$id" target)" || {
        echo "[-] Could not read target from manifest of '$id'." >&2
        return 1
    }
    sat_assessment_set_outputs "$dir"
    return 0
}

# sat_assessment_set_outputs [dir] - redirect per-phase artifacts into the
# assessment so phases stay isolated while keeping standalone defaults.
sat_assessment_set_outputs() {
    local dir="${1:-$ASSESSMENT_DIR}"
    export OUTPUT_NMAP="$dir/discovery"
    export OUTPUT_ENUM="$dir/enumeration"
    export OUTPUT_VULN="$dir/vulnerabilities"
    export OUTPUT_EXPLOIT="$dir/exploitation"
    export OUTPUT_EVIDENCE="$dir/evidence"
    export OUTPUT_REPORTS="$dir/report"
}

# ---------------------------------------------------------------
# Manifest access
# ---------------------------------------------------------------

sat_assessment_manifest_get() {
    local id="$1"
    local key="$2"
    local path="$ASSESSMENTS_ROOT/$id/manifest.json"
    [[ -f "$path" ]] || return 1
    python3 - "$path" "$key" 2>/dev/null <<'PY'
import json
import sys

path, key = sys.argv[1:3]
with open(path) as f:
    m = json.load(f)
v = m.get(key)
if v is None:
    sys.exit(1)
if isinstance(v, list):
    print(" ".join(str(x) for x in v))
else:
    print(v)
PY
}

# sat_assessment_manifest_set <id> <k1> <v1> [<k2> <v2> ...]
# Values may be JSON scalars or JSON arrays (e.g. '["a","b"]').
sat_assessment_manifest_set() {
    local id="$1"
    local path="$ASSESSMENTS_ROOT/$id/manifest.json"
    shift
    [[ -f "$path" ]] || return 1
    python3 - "$path" "$@" 2>/dev/null <<'PY'
import json
import sys

path = sys.argv[1]
kvs = sys.argv[2:]
with open(path) as f:
    m = json.load(f)
it = iter(kvs)
for key in it:
    value = next(it)
    if value.startswith("[") or value.startswith("{"):
        m[key] = json.loads(value)
    elif value in ("true", "false", "null"):
        m[key] = json.loads(value)
    else:
        m[key] = str(value)
with open(path, "w") as f:
    json.dump(m, f, indent=2)
    f.write("\n")
PY
}

sat_assessment_add_completed() {
    local id="$1" phase="$2"
    python3 - "$ASSESSMENTS_ROOT/$id/manifest.json" "$phase" 2>/dev/null <<'PY'
import json
import sys
from datetime import datetime, timezone

path, phase = sys.argv[1:3]
with open(path) as f:
    m = json.load(f)
for lst in ("completed_phases", "failed_phases"):
    if phase in m.get(lst, []):
        m[lst].remove(phase)
m.setdefault("completed_phases", []).append(phase)
m["current_phase"] = phase
m["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")
with open(path, "w") as f:
    json.dump(m, f, indent=2)
    f.write("\n")
PY
}

sat_assessment_add_failed() {
    local id="$1" phase="$2"
    python3 - "$ASSESSMENTS_ROOT/$id/manifest.json" "$phase" 2>/dev/null <<'PY'
import json
import sys
from datetime import datetime, timezone

path, phase = sys.argv[1:3]
with open(path) as f:
    m = json.load(f)
for lst in ("completed_phases", "failed_phases"):
    if phase in m.get(lst, []):
        m[lst].remove(phase)
m.setdefault("failed_phases", []).append(phase)
m["status"] = "failed"
m["current_phase"] = phase
m["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")
with open(path, "w") as f:
    json.dump(m, f, indent=2)
    f.write("\n")
PY
}

sat_assessment_is_completed() {
    local id="$1" phase="$2"
    python3 - "$ASSESSMENTS_ROOT/$id/manifest.json" "$phase" 2>/dev/null <<'PY'
import json
import sys

path, phase = sys.argv[1:3]
with open(path) as f:
    m = json.load(f)
sys.exit(0 if phase in m.get("completed_phases", []) else 1)
PY
}

# ---------------------------------------------------------------
# Artifact truth
# ---------------------------------------------------------------

# sat_assessment_phase_done <id> <phase> -> 0 when the phase has produced
# its marker artifact on disk (completion is never assumed from the
# manifest alone).
sat_assessment_phase_done() {
    local id="$1"
    local phase="$2"
    local base="$ASSESSMENTS_ROOT/$id"
    local dir="$base/$phase"
    local rc=1
    case "$phase" in
        discovery)
            compgen -G "$dir/"*.txt >/dev/null 2>&1 && rc=0
            compgen -G "$dir/"*.xml >/dev/null 2>&1 && rc=0
            ;;
        enumeration)
            compgen -G "$dir/"*.xml >/dev/null 2>&1 && rc=0
            compgen -G "$dir/"*.txt >/dev/null 2>&1 && rc=0
            ;;
        vulnerabilities)
            # services.tsv is only produced by the vulnerability module.
            compgen -G "$dir/"*_*/services.tsv >/dev/null 2>&1 && rc=0
            ;;
        correlation)
            # correlation writes into the shared OUTPUT_VULN dir tree.
            compgen -G "$base/vulnerabilities/"*_*/correlated_findings.tsv >/dev/null 2>&1 && rc=0
            ;;
        exploitation)
            compgen -G "$dir/"*_*/result.txt >/dev/null 2>&1 && rc=0
            ;;
        evidence)
            compgen -G "$dir/"*_*/session.txt >/dev/null 2>&1 && rc=0
            ;;
        report)
            compgen -G "$dir/"*_*.md >/dev/null 2>&1 && rc=0
            compgen -G "$dir/"*_*.html >/dev/null 2>&1 && rc=0
            ;;
        *)
            rc=1
            ;;
    esac
    return "$rc"
}

# ---------------------------------------------------------------
# Resume planning
# ---------------------------------------------------------------

# sat_assessment_build_plan <id> -> SAT_PLAN (space list of phases, in
# pipeline order). Never includes exploitation; evidence only when an
# exploitation result actually exists on disk.
sat_assessment_build_plan() {
    local id="$1" phase
    SAT_PLAN=""
    local exploit_done=0
    if sat_assessment_phase_done "$id" exploitation 2>/dev/null; then
        exploit_done=1
    fi
    for phase in "${SAT_PIPELINE[@]}"; do
        if [[ "$phase" == "evidence" && "$exploit_done" != 1 ]]; then
            continue
        fi
        if sat_assessment_is_completed "$id" "$phase" 2>/dev/null \
           && sat_assessment_phase_done "$id" "$phase" 2>/dev/null; then
            continue
        fi
        SAT_PLAN+=" $phase"
    done
    SAT_PLAN="${SAT_PLAN# }"
}