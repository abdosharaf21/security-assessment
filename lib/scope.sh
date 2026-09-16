#!/usr/bin/env bash
#
# Scope Management (Phase 10-11) - targets for one logical assessment scope.
# Source this file after lib/assessment.sh, do not execute it directly.
#
# Layering:
#   Assessment
#     └── Scope    (stable id: scope_<ts>)
#           └── Targets  (normalized, deduplicated, CIDR-expanded)
#
# Layout:
#   output/assessments/<assessment_id>/scopes/<scope_id>/
#     scope.json                      scope metadata (never secrets)
#     registry/<target_key>.json      per-target state
#     targets/<target_key>/<phase>/   per-target isolated artifacts
#
# A scope is never allowed to delete or replace previous results. Expansion
# only ADDS targets; whether previously completed targets are rescanned is
# an explicit user decision (--new / --failed / --all / --targets).

if [[ -n "${SAT_SCOPE_LOADED:-}" ]]; then
    return 0
fi
SAT_SCOPE_LOADED=1

# ---------------------------------------------------------------
# Locations
# ---------------------------------------------------------------

sat_scopes_root() {
    printf '%s' "$ASSESSMENTS_ROOT/$1/scopes"
}

sat_scope_dir() {
    printf '%s' "$ASSESSMENTS_ROOT/$1/scopes/$2"
}

sat_scope_meta_path() {
    printf '%s/scopes/%s/scope.json' "$ASSESSMENTS_ROOT/$1" "$2"
}

sat_scope_registry_dir() {
    printf '%s/scopes/%s/registry' "$ASSESSMENTS_ROOT/$1" "$2"
}

sat_scope_targets_dir() {
    printf '%s/scopes/%s/targets' "$ASSESSMENTS_ROOT/$1" "$2"
}

sat_scope_target_dir() {
    printf '%s/scopes/%s/targets/%s' "$ASSESSMENTS_ROOT/$1" "$2" "$(sat_safe_name "${3:-}")"
}

# ---------------------------------------------------------------
# IDs / resolution
# ---------------------------------------------------------------

sat_scope_id_new() {
    local base id ts n=0
    while true; do
        ts="$(date '+%Y%m%d_%H%M%S%N' 2>/dev/null || date '+%Y%m%d_%H%M%S')"
        id="scope_${ts}"
        # ids are unique per assessment root
        if [[ ! -e "$ASSESSMENTS_ROOT"/"$id" ]] \
           && ! compgen -G "$ASSESSMENTS_ROOT"/*/scopes/"$id" >/dev/null 2>&1; then
            printf '%s' "$id"
            return 0
        fi
        n=$((n + 1))
        if (( n > 100 )); then
            id="scope_$(date '+%Y%m%d_%H%M%S%N')_${n}"
            printf '%s' "$id"
            return 0
        fi
    done
}

# sat_scope_find_assessment <scope_id> -> prints the owning assessment id
# (or empty). Searches the current ASSESSMENTS_ROOT.
sat_scope_find_assessment() {
    local sid="$1" aid dir
    for aid in "$ASSESSMENTS_ROOT"/assessment_*; do
        [[ -d "$aid" ]] || continue
        dir="$aid/scopes/$sid"
        if [[ -f "$dir/scope.json" ]]; then
            printf '%s' "$(basename "$aid")"
            return 0
        fi
    done
    return 1
}

# sat_scope_resolve <scope_id> -> exports SAT_SCOPE_ASSESSMENT, SAT_SCOPE_ID,
# SAT_SCOPE_DIR. Returns 0 only for existing scopes.
sat_scope_resolve() {
    local sid="${1:-}" aid
    [[ -n "$sid" ]] || return 1
    [[ "$sid" == scope_* ]] || return 1
    aid="$(sat_scope_find_assessment "$sid")" || return 1
    SAT_SCOPE_ASSESSMENT="$aid"
    SAT_SCOPE_ID="$sid"
    SAT_SCOPE_DIR="$(sat_scope_dir "$aid" "$sid")"
    return 0
}

# ---------------------------------------------------------------
# Target normalization / CIDR expansion (Phase 10.3-10.4)
# ---------------------------------------------------------------

# sat_scope_normalize <max> <tokens...> -> prints one normalized, deduplicated
# target per line (CIDR ranges expanded). Exits 1 with a message on any
# invalid/oversized input. Never expands the same host twice.
sat_scope_normalize() {
    local max="${1:-${SCOPE_MAX_EXPANDED_TARGETS:-256}}"
    shift
    python3 - "$max" "$@" <<'PY' || return 1
import ipaddress
import sys

maxv = int(sys.argv[1])
tokens = [t for tok in sys.argv[2:] for t in tok.split(",")]
tokens = [t for t in tokens if t]

BAD = set("; & | > < ` $ ( ) { }")


def valid_token(t):
    if not t or t.startswith("-"):
        return False
    if any(c in BAD for c in t):
        return False
    if any(c.isspace() for c in t):
        return False
    return True


def expand(tok):
    """Return list of hosts, or None if the token is invalid."""
    if not valid_token(tok):
        return None
    if "/" in tok:  # CIDR required
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except (ValueError, TypeError):
            return None
        if net.version != 4:
            return None
        # network + broadcast addresses are not hosts
        hosts = [str(h) for h in net.hosts()]
        if len(hosts) > maxv:
            raise OverflowError((tok, len(hosts), maxv))
        return hosts
    try:
        ip = ipaddress.ip_address(tok)
        if ip.version != 4:
            return None
        return [str(ip)]
    except ValueError:
        # hostname (supported where meaningful: no metachars, no slash)
        return [tok.lower()]


out = []
seen = set()
for tok in tokens:
    try:
        hosts = expand(tok)
    except OverflowError as e:
        sys.stderr.write("CIDR expansion refused for %s (%d hosts > limit %d)\n" % e.args)
        sys.exit(1)
    if hosts is None:
        sys.stderr.write("Invalid scope target: '%s'\n" % tok)
        sys.exit(1)
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)

for h in out:
    print(h)
PY
}

# sat_scope_scope_type <tokens...> -> crude scope type classification from
# the raw input, used for metadata only.
sat_scope_scope_type() {
    local t
    for t in "$@"; do
        [[ "$t" == *"/"* ]] && { printf 'cidr'; return; }
        if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            continue
        fi
        printf 'hostname'
        return
    done
    printf 'ip'
}

# ---------------------------------------------------------------
# Scope metadata (JSON, plain metadata only - never secrets)
# ---------------------------------------------------------------

sat_scope_meta_get() {
    local aid="${SAT_SCOPE_ASSESSMENT:-}" sid="$1" key="$2" path
    if [[ -z "$aid" ]]; then
        aid="$(sat_scope_find_assessment "$sid")" || return 1
    fi
    path="$(sat_scope_meta_path "$aid" "$sid")"
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
    print("\n".join(str(x) for x in v))
else:
    print(v)
PY
}

sat_scope_meta_set() {
    local aid="${SAT_SCOPE_ASSESSMENT:-}" sid="$1" path
    shift
    if [[ -z "$aid" ]]; then
        aid="$(sat_scope_find_assessment "$sid")" || return 1
    fi
    path="$(sat_scope_meta_path "$aid" "$sid")"
    [[ -f "$path" ]] || return 1
    python3 - "$path" "$@" 2>/dev/null <<'PY'
import json
import sys
path = sys.argv[1]
kvs = sys.argv[2:]
m = json.load(open(path))
it = iter(kvs)
for key in it:
    value = next(it)
    if isinstance(value, str) and (value.startswith("[") or value.startswith("{")):
        m[key] = json.loads(value)
    elif value in ("true", "false", "null"):
        m[key] = json.loads(value)
    else:
        m[key] = value
with open(path, "w") as f:
    json.dump(m, f, indent=2)
    f.write("\n")
PY
}

# ---------------------------------------------------------------
# Create / expand
# ---------------------------------------------------------------

# sat_scope_create <assessment_id> <targets...> [--name <n>] [--parent <sid>]
# Creates the assessment shell when needed. Prints the new scope id.
sat_scope_create() {
    local aid="${1:-}" sid new_id now name="auto" parent="" scope_type
    shift
    [[ -n "$aid" ]] || { echo "[-] scope create requires <assessment_id>" >&2; return 1; }
    local targets=()
    while (( $# > 0 )); do
        case "$1" in
            --name) name="${2:-auto}"; shift 2 ;;
            --parent) parent="${2:-}"; shift 2 ;;
            *) targets+=("$1"); shift ;;
        esac
    done

    if ! sat_assessment_ensure "$aid"; then
        return 1
    fi

    local normalized
    normalized="$(sat_scope_normalize "${SCOPE_MAX_EXPANDED_TARGETS:-256}" "${targets[@]}")" || return 1
    scope_type="$(sat_scope_scope_type "${targets[@]}")"
    [[ "$name" == "auto" ]] && name="Scope $(( $(sat_scope_list_count "$aid") + 1 ))"

    new_id="$(sat_scope_id_new)" || return 1
    local dir reg tdir target
    dir="$(sat_scope_dir "$aid" "$new_id")"
    mkdir -p "$dir" || return 1
    reg="$(sat_scope_registry_dir "$aid" "$new_id")"
    mkdir -p "$reg"
    tdir="$(sat_scope_targets_dir "$aid" "$new_id")"
    mkdir -p "$tdir"
    now="$(date '+%Y-%m-%dT%H:%M:%S%z')"

    python3 - "$dir/scope.json" "$new_id" "$aid" "$now" "$name" "$parent" "$(printf '%s' "$scope_type")" "$normalized" <<'PY' || return 1
import json
import sys

path, sid, aid, now, name, parent, stype = sys.argv[1:8]
targets = sys.argv[8].split("\n") if sys.argv[8] else []
scope = {
    "scope_id": sid,
    "assessment_id": aid,
    "name": name,
    "type": stype,
    "targets": targets,
    "created_at": now,
    "status": "pending",
    "parent_scope_id": parent or None,
    "target_count": len(targets),
    "completed_target_count": 0,
    "last_run": None,
}
with open(path, "w") as f:
    json.dump(scope, f, indent=2)
    f.write("\n")
PY

    for target in $normalized; do
        sat_scope_target_stub "$aid" "$new_id" "$target"
        mkdir -p "$(sat_scope_target_dir "$aid" "$new_id" "$target")"
    done

    echo "[+] Scope created: $new_id (assessment $aid)"
    echo "    name: $name | type: $scope_type | targets: $(wc -l <<<"$normalized")"
    echo
    echo "    Scan it with:"
    echo "      $0 scan $new_id               # new targets only (conservative)"
    echo "      $0 scan $new_id --all         # rescan every target"
    echo "      $0 scan $new_id --failed      # retry failed targets"
}

# sat_scope_list_count <assessment_id> -> number of scopes in the assessment
sat_scope_list_count() {
    local aid="$1" sid
    local n=0
    for sid in "$(sat_scopes_root "$aid")"/*/; do
        [[ -d "$sid" ]] || continue
        n=$((n + 1))
    done
    printf '%s' "$n"
}

# sat_scope_expand <scope_id> <targets...> -> ADDS targets to an existing
# scope. Previous results are never deleted or replaced. Reports how many
# targets were already assessed (existing) vs added (new).
sat_scope_expand() {
    local sid="${1:-}" aid
    shift
    [[ -n "$sid" ]] || { echo "[-] scope expand requires <scope_id>" >&2; return 1; }
    sat_scope_resolve "$sid" || { echo "[-] Unknown scope: $sid" >&2; return 1; }
    aid="$SAT_SCOPE_ASSESSMENT"

    local normalized existing new_count=0 existing_count=0 dupes=0
    normalized="$(sat_scope_normalize "${SCOPE_MAX_EXPANDED_TARGETS:-256}" "$@")" || return 1

    local have t
    have="$(sat_scope_meta_get "$sid" targets || true)"
    for t in $normalized; do
        if grep -qxF "$t" <<<"$have"; then
            existing_count=$((existing_count + 1))
            continue
        fi
        new_count=$((new_count + 1))
        SAT_SCOPE_NEW_TARGETS+=" $t"
    done

    if (( new_count == 0 && existing_count == 0 )); then
        echo "[-] No valid targets to add." >&2
        return 1
    fi

    if (( existing_count > 0 )); then
        echo "[*] $existing_count target(s) already in scope (not re-added):"
        local shown=0
        for t in $normalized; do
            grep -qxF "$t" <<<"$have" || continue
            (( shown < 5 )) && echo "      $t"
            shown=$((shown + 1))
        done
        (( existing_count <= 5 )) || echo "      ... and $(( existing_count - 5 )) more"
        echo
    fi

    if (( new_count > 0 )); then
        local arr=""
        for t in $normalized; do
            grep -qxF "$t" <<<"$have" && continue
            arr+=" \"$t\""
            sat_scope_target_stub "$aid" "$sid" "$t"
            mkdir -p "$(sat_scope_target_dir "$aid" "$sid" "$t")"
        done
        # append new targets to the scope metadata targets array
        python3 - "$(sat_scope_meta_path "$aid" "$sid")" "$have" "$new_count" "$arr" <<'PY' || return 1
import json
import sys

path = sys.argv[1]
existing_lines = sys.argv[2].split("\n")
append = json.loads("[" + sys.argv[4] + "]")
new_count = int(sys.argv[3])
m = json.load(open(path))
cur = m.get("targets", [])
merged = cur + [t for t in append if t not in cur]
m["targets"] = merged
m["target_count"] = len(merged)
with open(path, "w") as f:
    json.dump(m, f, indent=2)
    f.write("\n")
PY
        echo "[+] Added $new_count new target(s) to scope $sid."
        for t in $SAT_SCOPE_NEW_TARGETS; do
            echo "    + $t"
        done
        echo
        echo "    Previously completed targets were NOT rescanned."
        echo "    Next step (scan only the new targets):"
        echo "      $0 scan $sid --new"
    else
        echo "[*] No new targets to add - $sid already contains them."
    fi
    return 0
}

# ---------------------------------------------------------------
# Per-target state (Phase 11.1)
# ---------------------------------------------------------------

sat_scope_target_stub() {
    local aid="$1" sid="$2" target="$3" key
    key="$(sat_safe_name "$target")"
    python3 - "$(sat_scope_registry_dir "$aid" "$sid")/$key.json" "$target" "$key" <<'PY' || return 1
import json
import sys
path, target, key = sys.argv[1:4]
doc = {
    "target": target,
    "key": key,
    "state": "pending",
    "phases": {},
    "reason": "",
    "last_rc": None,
    "last_run": None,
}
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
}

sat_scope_target_registry_path() {
    local aid="${SAT_SCOPE_ASSESSMENT:-}" sid="$1" target="$2"
    if [[ -z "$aid" ]]; then
        aid="$(sat_scope_find_assessment "$sid")" || return 1
    fi
    printf '%s/scopes/%s/registry/%s.json' "$ASSESSMENTS_ROOT/$aid" "$sid" "$(sat_safe_name "$target")"
}

# Generic read-write of a target registry doc.
sat_scope_target_update() {
    local sid="$1" target="$2"
    shift 2
    local path
    path="$(sat_scope_target_registry_path "$sid" "$target")" || return 1
    [[ -f "$path" ]] || return 1
    python3 - "$path" "$@" 2>/dev/null <<'PY'
import json
import sys

path = sys.argv[1]
kvs = sys.argv[2:]
doc = json.load(open(path))
it = iter(kvs)
for key in it:
    value = next(it)
    if isinstance(key, str) and key == "phases":
        # phases is set as a JSON object
        doc["phases"] = json.loads(value)
        continue
    if isinstance(value, str) and value.startswith("{"):
        doc[key] = json.loads(value)
    elif value in ("true", "false", "null"):
        doc[key] = json.loads(value)
    elif value == "__none__":
        doc[key] = None
    else:
        doc[key] = value
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
}

sat_scope_target_state() {
    local sid="$1" target="$2" path
    path="$(sat_scope_target_registry_path "$sid" "$target")" || { printf 'pending'; return; }
    [[ -f "$path" ]] || { printf 'pending'; return; }
    python3 - "$path" 2>/dev/null <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get("state", "pending"))
PY
}

# Set state=running with a started timestamp.
sat_scope_target_begin() {
    local sid="$1" target="$2"
    sat_scope_target_update "$sid" "$target" state running reason "" last_run "$(date '+%Y-%m-%dT%H:%M:%S%z')" 2>/dev/null
}

# Record the outcome of one phase for one target.
sat_scope_target_phase() {
    local sid="$1" target="$2" phase="$3" status="$4" rc="$5"
    # merge into the phases object without clobbering unrelated keys
    local path
    path="$(sat_scope_target_registry_path "$sid" "$target")" || return 1
    [[ -f "$path" ]] || return 1
    python3 - "$path" "$phase" "$status" "$rc" 2>/dev/null <<'PY'
import json
import sys
path, phase, status, rc = sys.argv[1:5]
doc = json.load(open(path))
doc.setdefault("phases", {})[phase] = {"status": status, "rc": int(rc)}
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
}

sat_scope_target_complete() {
    sat_scope_target_update "$1" "$2" state completed reason "" 2>/dev/null
}

sat_scope_target_fail() {
    local sid="$1" target="$2" reason="$3" rc="$4"
    sat_scope_target_update "$sid" "$target" state failed reason "$reason" last_rc "$rc" 2>/dev/null
}

# TERM-abort handler (worker timed out and was killed).
sat_scope_target_abort() {
    local aid="${SAT_SCOPE_ASSESSMENT:-}" sid="$1" target="$2" reason="$3" rc="$4"
    if [[ -z "$aid" ]]; then
        aid="$(sat_scope_find_assessment "$sid")" || return 1
    fi
    sat_scope_target_fail "$sid" "$target" "${reason:-timeout}" "${rc:-124}"
    python3 - "$(sat_scope_meta_path "$aid" "$sid")" "$sid" <<'PY' >/dev/null 2>&1 || true
import json, sys
path, sid = sys.argv[1:3]
m = json.load(open(path))
m["status"] = "failed"
m["last_run"] = __import__("datetime").datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
with open(path, "w") as f:
    json.dump(m, f, indent=2)
    f.write("\n")
PY
    return 0
}

# ---------------------------------------------------------------
# Selection / summary (Phase 11.2)
# ---------------------------------------------------------------

# sat_scope_selected <scope_id> <mode> [-- target...]
#   mode: pending|new|failed|all|selected
# Prints the targets to process (one per line). Nothing is run here.
sat_scope_selected() {
    local sid="$1" mode="${2:-pending}" aid target state
    sat_scope_resolve "$sid" || { echo "[-] Unknown scope: $sid" >&2; return 1; }
    aid="$SAT_SCOPE_ASSESSMENT"
    shift 2
    local sel=()
    if [[ "$mode" == "selected" ]]; then
        sel=("$@")
    fi

    local targets list=""
    targets="$(sat_scope_meta_get "$sid" targets || true)"
    while IFS= read -r target; do
        [[ -n "$target" ]] || continue
        if [[ "$mode" == "selected" ]]; then
            local have=0 want
            for want in "${sel[@]}"; do
                [[ "$(sat_safe_name "$want")" == "$(sat_safe_name "$target")" ]] && have=1
            done
            (( have == 1 )) || continue
            list+=" $target"
            continue
        fi
        state="$(sat_scope_target_state "$sid" "$target")"
        case "$mode" in
            pending|new)
                # "running" that no longer has a live worker is treated as
                # recoverable/pending (crashed/interrupted assignment).
                [[ "$state" == "pending" || "$state" == "running" ]] || continue
                ;;
            failed)
                [[ "$state" == "failed" ]] || continue
                ;;
            all)
                :
                ;;
        esac
        list+=" $target"
    done <<<"$targets"
    printf '%s' "${list# }"
}

# sat_scope_summary <scope_id> -> updates scope.json state/counts and prints
# a per-target table.
sat_scope_summary() {
    local sid="$1" aid
    sat_scope_resolve "$sid" || return 1
    aid="$SAT_SCOPE_ASSESSMENT"

    local target targets state total=0 completed=0 failed=0 pending=0 running=0
    targets="$(sat_scope_meta_get "$sid" targets || true)"
    echo
    echo "[*] Scope status: $sid ($(sat_scope_meta_get "$sid" name))"
    while IFS= read -r target; do
        [[ -n "$target" ]] || continue
        state="$(sat_scope_target_state "$sid" "$target")"
        total=$((total + 1))
        case "$state" in
            completed) completed=$((completed + 1)) ;;
            failed) failed=$((failed + 1)) ;;
            running) running=$((running + 1)) ;;
            *) pending=$((pending + 1)) ;;
        esac
        printf '    %-20s %s\n' "$target" "$state"
    done <<<"$targets"

    SAT_SCOPE_TOTAL=$total
    SAT_SCOPE_COMPLETED=$completed
    SAT_SCOPE_FAILED=$failed
    SAT_SCOPE_PENDING=$pending

    local status="pending"
    if (( running > 0 )); then
        status="running"
    elif (( total > 0 && completed == total )); then
        status="completed"
    elif (( failed > 0 )); then
        status="failed"
    elif (( completed > 0 )); then
        status="in_progress"
    fi
    sat_scope_meta_set "$sid" status "$status" completed_target_count "$completed"
    echo
    echo "    targets: $total | completed: $completed | failed: $failed | pending: $pending"
    echo "    scope status: $status"
}