#!/usr/bin/env python3
#
# Shared, read-only reader for immutable historical assessments (Phase 12).
#
# This is a pure-stdlib helper that turns the on-disk assessment layout into a
# small normalized "evidence" model used by both `history` and `compare`.
# It NEVER writes, moves, or rewrites any historical artifact.
#
# Layouts understood (corresponding to the existing implementation):
#   single-target assessment:
#     <root>/<aid>/manifest.json
#     <root>/<aid>/<phase>/<safe_target>_<ts>.(txt|xml|dir/)
#   scope-based assessment:
#     <root>/<aid>/scopes/<sid>/scope.json
#     <root>/<aid>/scopes/<sid>/registry/<key>.json
#     <root>/<aid>/scopes/<sid>/targets/<key>/<phase>/...
#
# Phase statuses are derived from real artifacts plus the authoritative
# per-target state machine (manifest completed/failed_phases for single-target
# assessments, scope registry for scope targets). Artifacts always win over
# state files when an artifact exists; absence is recorded as not-run/failed,
# never as negative evidence.
#
# Rules honored here:
#   * FAILED != NOT OBSERVED
#   * DEPENDENCY MISSING != FINDING REMOVED
#   * NO EVIDENCE != NEGATIVE EVIDENCE
#   * historical data is never modified

import glob
import json
import os
import re
import xml.etree.ElementTree as ET

PHASES = ("discovery", "enumeration", "vulnerabilities", "correlation",
          "exploitation", "evidence", "report")

PHASE_LABELS = {
    "discovery": "discovery",
    "enumeration": "enumeration",
    "vulnerabilities": "vulnerabilities",
    "correlation": "correlation",
    "exploitation": "exploitation",
    "evidence": "evidence",
    "report": "report",
}


class EvidenceError(Exception):
    """Raised when a historical record cannot be trusted / read."""
    pass


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(text or ""))


def kv_items(path):
    """Parse a module status.txt / result.txt into a dict (best effort)."""
    out = {}
    if not os.path.isfile(path):
        return out
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def tsv_rows(path):
    """Parse a TSV with a header row into a list of dicts."""
    rows = []
    if not os.path.isfile(path):
        return rows
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return rows
    if not lines:
        return []
    header = lines[0].split("\t")
    for line in lines[1:]:
        if not line.strip():
            continue
        cells = line.split("\t")
        row = {}
        for i, h in enumerate(header):
            row[h] = cells[i] if i < len(cells) else ""
        rows.append(row)
    return rows


def latest_matching(pattern, directories=True, files=True):
    """Lexically-latest path matching glob (lexicographic == chronological
    here because artifact names embed an ascending timestamp)."""
    cands = glob.glob(pattern)
    if not cands:
        return None
    if directories and files:
        cands = [c for c in cands if os.path.isdir(c) or os.path.isfile(c)]
    elif directories:
        cands = [c for c in cands if os.path.isdir(c)]
    else:
        cands = [c for c in cands if os.path.isfile(c)]
    if not cands:
        return None
    return sorted(cands)[-1]


def candidates(pattern):
    c = glob.glob(pattern)
    c.sort()
    return c


def has_host_up(txt_path):
    """True when a discovery .txt records the host as up."""
    try:
        with open(txt_path, "r", encoding="utf-8", errors="replace") as fh:
            return bool(re.search(r"Host is up", fh.read()))
    except OSError:
        return None


def xml_host_up(xml_path):
    try:
        root = ET.parse(xml_path).getroot()
    except Exception:
        return None
    for host in root.findall("host"):
        st = host.find("status")
        if st is not None and st.get("state") in ("up", "down"):
            return st.get("state") == "up"
    return None


def parse_xml_ports(xml_path):
    """Return list of open ports from an Nmap XML, or None if unreadable."""
    try:
        root = ET.parse(xml_path).getroot()
    except Exception:
        return None
    ports = []
    for host in root.findall("host"):
        st = host.find("status")
        if st is not None and st.get("state") == "down":
            continue
        ports_node = host.find("ports")
        if ports_node is None:
            continue
        for port in ports_node.findall("port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            rec = {
                "port": port.get("portid", ""),
                "protocol": port.get("protocol", "tcp"),
                "service": "",
                "product": "",
                "version": "",
                "extrainfo": "",
                "cpe": "",
            }
            svc = port.find("service")
            if svc is not None:
                rec["service"] = svc.get("name", "")
                rec["product"] = svc.get("product", "")
                rec["version"] = svc.get("version", "")
                rec["extrainfo"] = svc.get("extrainfo", "")
                cpes = [c.text.strip() for c in svc.findall("cpe") if c.text]
                rec["cpe"] = ";".join(sorted(set(cpes)))
            ports.append(rec)
    return ports


# ------------------------------------------------------------------
# Assessment / manifest
# ------------------------------------------------------------------

def load_manifest(root, aid):
    """Validate and load an assessment manifest. Raises EvidenceError when the
    history cannot be trusted (never fabricates a partial record)."""
    if not aid:
        raise EvidenceError("missing assessment id")
    if not aid.startswith("assessment_"):
        raise EvidenceError("invalid assessment id: '%s' (must start with 'assessment_')" % aid)
    adir = os.path.join(root, aid)
    if not os.path.isdir(adir):
        raise EvidenceError("unknown assessment: %s" % aid)
    mpath = os.path.join(adir, "manifest.json")
    if not os.path.isfile(mpath):
        raise EvidenceError("assessment '%s' has no manifest.json (missing historical state)." % aid)
    try:
        with open(mpath, "r", encoding="utf-8") as fh:
            m = json.load(fh)
    except Exception:
        raise EvidenceError(
            "assessment '%s' has a missing or corrupt manifest (refusing to fabricate state)." % aid)
    if not isinstance(m, dict) or m.get("assessment_id") != aid:
        raise EvidenceError(
            "assessment '%s' has a missing or corrupt manifest (refusing to fabricate state)." % aid)
    scopes_root = os.path.join(adir, "scopes")
    has_scopes = os.path.isdir(scopes_root) and bool(candidates(
        os.path.join(scopes_root, "scope_*")))
    kind = "scope" if (m.get("scope_based") or has_scopes) else "single"
    return m, kind


def assessment_dir(root, aid):
    return os.path.join(root, aid)


def list_scopes(manifest, adir, kind):
    """Return per-scope metadata dicts (scope-based kind only)."""
    scopes = []
    if kind != "scope":
        return scopes
    for sd in candidates(os.path.join(adir, "scopes", "scope_*")):
        if not os.path.isdir(sd):
            continue
        sid = os.path.basename(sd)
        rec = {"scope_id": sid, "dir": sd, "scope": None, "missing_meta": False}
        sp = os.path.join(sd, "scope.json")
        if os.path.isfile(sp):
            try:
                with open(sp, "r", encoding="utf-8") as fh:
                    rec["scope"] = json.load(fh)
            except Exception:
                rec["missing_meta"] = True
        else:
            rec["missing_meta"] = True
        scopes.append(rec)
    return scopes


def list_targets(manifest, adir, kind):
    """Stable per-assessment target list (deduplicated, sorted for display
    later). Identity is the target string itself, not the scope."""
    seen = []
    if kind == "single":
        t = (manifest.get("target") or "").strip()
        return [t] if t else []
    for sid_dir in candidates(os.path.join(adir, "scopes", "scope_*")):
        sp = os.path.join(sid_dir, "scope.json")
        if not os.path.isfile(sp):
            continue
        try:
            with open(sp, "r", encoding="utf-8") as fh:
                s = json.load(fh)
        except Exception:
            continue
        for t in (s.get("targets") or []):
            if not str(t).strip():
                continue
            if str(t).strip() not in seen:
                seen.append(str(t).strip())
    return seen


# ------------------------------------------------------------------
# Per-target phase state from the authoritative state machine
# ------------------------------------------------------------------

def fallback_phase_states(manifest, adir_scope_or_none, kind, key, sid=None):
    """Authoritative phase statuses used only when artifacts are absent:
    single-target -> manifest completed/failed_phases
    scope target  -> scope registry phases dict."""
    fallback = {}
    if kind == "single":
        for p in (manifest.get("completed_phases") or []):
            fallback[PHASE_LABELS.get(p, p)] = "completed"
        for p in (manifest.get("failed_phases") or []):
            fallback[PHASE_LABELS.get(p, p)] = "failed"
        return fallback
    reg_path = os.path.join(adir_scope_or_none, "registry", "%s.json" % key)
    if os.path.isfile(reg_path):
        try:
            with open(reg_path, "r", encoding="utf-8") as fh:
                reg = json.load(fh)
        except Exception:
            return fallback
    else:
        return fallback
    phases = reg.get("phases") or {}
    for name, rec in phases.items():
        if isinstance(rec, dict):
            fallback.setdefault(name, rec.get("status"))
        elif isinstance(rec, str):
            fallback.setdefault(name, rec)
    return fallback


# ------------------------------------------------------------------
# Artifact extraction for one unit (a phase-root that contains phase
# subdirectories: either a scope target dir or a single-target assessment dir)
# ------------------------------------------------------------------

NOT_RUN = "not-run"


def read_evidence_unit(unit, prefix, fallback):
    """Read all phase evidence for one target execution unit.

    unit     - directory containing phase subdirs (discovery/, enumeration/, ...)
    prefix   - safe target key used in artifact names
    fallback - authoritative phase statuses when artifacts are missing
    Returns an evidence dict keyed by phase label.
    """
    ev = {
        "discovery": {"status": NOT_RUN, "up": None, "artifact": None, "reason": ""},
        "enumeration": {"status": NOT_RUN, "ports": [], "open_ports": 0,
                        "no_open_ports": False, "artifact": None, "reason": ""},
        "vulnerabilities": {"status": NOT_RUN, "services": [], "candidates": [],
                            "dir": None, "reason": ""},
        "correlation": {"status": NOT_RUN, "findings": [], "dir": None, "reason": ""},
        "exploitation": {"status": NOT_RUN, "session_id": None, "session_type": None,
                         "selected_module": None, "candidate_title": None, "dir": None,
                         "reason": ""},
        "evidence": {"status": NOT_RUN, "session_id": None, "dir": None, "reason": ""},
        "report": {"status": ("completed" if latest_matching(
            os.path.join(unit, "report", prefix + "_*.md"), directories=False) or
            latest_matching(os.path.join(unit, "report", prefix + "_*.html"),
                            directories=False) else NOT_RUN),
            "artifact": None},
    }

    # ---- discovery
    txt = latest_matching(os.path.join(unit, "discovery", prefix + "_*.txt"), directories=False)
    if txt:
        up = has_host_up(txt)
        ev["discovery"] = {"status": "completed", "up": up, "artifact": txt, "reason": ""}
    else:
        xml = latest_matching(os.path.join(unit, "discovery", prefix + "_*.xml"), directories=False)
        if xml:
            up = xml_host_up(xml)
            ev["discovery"] = {"status": "completed", "up": up, "artifact": xml, "reason": ""}
    if ev["discovery"]["status"] == NOT_RUN and fallback.get("discovery") == "failed":
        ev["discovery"] = {"status": "failed", "up": None, "artifact": None,
                           "reason": fallback.get("reason", "")}

    # ---- enumeration
    xml = latest_matching(os.path.join(unit, "enumeration", prefix + "_*.xml"), directories=False)
    if xml:
        ports = parse_xml_ports(xml)
        if ports is not None:
            ev["enumeration"] = {
                "status": "completed",
                "ports": ports,
                "open_ports": len(ports),
                "no_open_ports": len(ports) == 0,
                "artifact": xml,
                "reason": "",
            }
    if ev["enumeration"]["status"] == NOT_RUN:
        txt = latest_matching(os.path.join(unit, "enumeration", prefix + "_*.txt"),
                              directories=False)
        if txt:
            try:
                with open(txt, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                content = ""
            closed = bool(re.search(r"closed[[:space:]]", content)) or \
                bool(re.search(r"no open", content, flags=re.IGNORECASE))
            if closed:
                ev["enumeration"] = {"status": "completed", "ports": [], "open_ports": 0,
                                     "no_open_ports": True, "artifact": txt, "reason": ""}
    if ev["enumeration"]["status"] == NOT_RUN and fallback.get("enumeration") == "failed":
        ev["enumeration"] = {"status": "failed", "ports": [], "open_ports": 0,
                             "no_open_ports": False, "artifact": None,
                             "reason": fallback.get("reason", "")}

    # ---- vulnerabilities (research) + correlation (separate)
    vdirs = candidates(os.path.join(unit, "vulnerabilities", prefix + "_*"))
    research_dirs = [d for d in vdirs
                     if os.path.isfile(os.path.join(d, "services.tsv"))]
    corr_dirs = [d for d in vdirs
                 if os.path.isfile(os.path.join(d, "correlated_findings.tsv"))]
    dep_dirs = [d for d in vdirs
                if kv_items(os.path.join(d, "status.txt")).get("status") == "dependency-missing"]

    if research_dirs:
        d = research_dirs[-1]
        status_txt = kv_items(os.path.join(d, "status.txt"))
        st = status_txt.get("status", "completed")
        ev["vulnerabilities"] = {
            "status": "completed" if st == "completed" else st,
            "services": tsv_rows(os.path.join(d, "services.tsv")),
            "candidates": tsv_rows(os.path.join(d, "exploitdb_candidates.tsv")),
            "dir": d,
            "reason": "" if st == "completed" else ("vulnerability research: %s" % st),
        }
    elif dep_dirs:
        d = dep_dirs[-1]
        kv = kv_items(os.path.join(d, "status.txt"))
        ev["vulnerabilities"] = {
            "status": "dependency-missing",
            "services": [],
            "candidates": [],
            "dir": d,
            "reason": "dependency missing: %s" % (kv.get("dependency") or "unknown"),
        }
    else:
        fb = fallback.get("vulnerabilities")
        if fb == "failed":
            ev["vulnerabilities"] = {"status": "failed", "services": [], "candidates": [],
                                     "dir": None, "reason": fallback.get("reason", "")}

    if corr_dirs:
        d = corr_dirs[-1]
        status_txt = kv_items(os.path.join(d, "status.txt"))
        st = status_txt.get("status", "completed")
        ev["correlation"] = {
            "status": "completed" if st == "completed" else st,
            "findings": tsv_rows(os.path.join(d, "correlated_findings.tsv")),
            "dir": d,
            "reason": "" if st == "completed" else ("correlation: %s" % st),
        }
    elif fallback.get("correlation") == "failed":
        ev["correlation"] = {"status": "failed", "findings": [], "dir": None,
                             "reason": fallback.get("reason", "")}

    # ---- exploitation
    xd = latest_matching(os.path.join(unit, "exploitation", prefix + "_*"))
    if xd:
        result = kv_items(os.path.join(xd, "result.txt"))
        st_txt = kv_items(os.path.join(xd, "status.txt"))
        st = (result.get("session_status") or st_txt.get("status") or "failed")
        ev["exploitation"] = {
            "status": st,
            "session_id": result.get("session_id") or None,
            "session_type": result.get("session_type") or None,
            "selected_module": result.get("selected_module") or None,
            "candidate_title": result.get("candidate_title") or None,
            "dir": xd,
            "reason": "" if st in ("session-created", "no-session")
                      else ("exploitation: %s" % st),
        }

    # ---- evidence
    ed = latest_matching(os.path.join(unit, "evidence", prefix + "_*"))
    if ed:
        sess = kv_items(os.path.join(ed, "session.txt"))
        st_txt = kv_items(os.path.join(ed, "status.txt"))
        st = (sess.get("session_status") or st_txt.get("status") or "unknown")
        ev["evidence"] = {
            "status": st,
            "session_id": sess.get("session_id") or None,
            "dir": ed,
            "reason": "" if st in ("session-created", "no-session")
                      else ("evidence: %s" % st),
        }

    # ---- report
    rep = latest_matching(os.path.join(unit, "report", prefix + "_*.md"), directories=False) or \
        latest_matching(os.path.join(unit, "report", prefix + "_*.html"), directories=False)
    if rep:
        ev["report"]["artifact"] = rep

    return ev


# ------------------------------------------------------------------
# Target evidence collection (merges execution units across scopes)
# ------------------------------------------------------------------

PREFERENCE = {"completed": 0, "dependency-missing": 1, "failed": 2, NOT_RUN: 3, "unknown": 4}


def _better(a, b):
    """Pick the more informative evidence record for the same aspect."""
    if b is None:
        return a
    if a is None:
        return b
    pa = PREFERENCE.get(a.get("status", NOT_RUN), 9)
    pb = PREFERENCE.get(b.get("status", NOT_RUN), 9)
    if pa != pb:
        return a if pa < pb else b
    # same preference: prefer the record with a real artifact (newer run)
    dir_a = a.get("artifact") or a.get("dir")
    dir_b = b.get("artifact") or b.get("dir")
    if dir_a and dir_b:
        return a if dir_a >= dir_b else b
    if dir_a:
        return a
    if dir_b:
        return b
    return a


def collect_target_evidence(root, aid, target, sources=None):
    """Return the merged evidence model for one stable target across every
    scope in the assessment (or the single-target layout)."""
    manifest, kind = load_manifest(root, aid)
    adir = assessment_dir(root, aid)
    key = safe_name(target)
    sources = sources if sources is not None else {}

    units = []
    if kind == "single":
        units.append({"kind": "single", "unit": adir,
                      "fallback": fallback_phase_states(manifest, None, kind, key)})
    else:
        for scope in list_scopes(manifest, adir, kind):
            s = scope.get("scope") or {}
            if target not in (s.get("targets") or []):
                continue
            sid = scope["scope_id"]
            unit_root = os.path.join(adir, "scopes", sid, "targets", key)
            units.append({"kind": "scope", "unit": unit_root, "sid": sid,
                          "fallback": fallback_phase_states(
                              manifest, os.path.join(adir, "scopes", sid), kind, key, sid)})

    merged = {
        "target": target,
        "key": key,
        "kind": kind,
        "scopes": sorted({u["sid"] for u in units if u.get("sid")}),
        "single": kind == "single",
        "missing_execution": len(units) == 0,
    }
    # seed aspects from modules not covered by the worker state machine
    aspects_in_order = ["discovery", "enumeration", "vulnerabilities", "correlation",
                        "exploitation", "evidence", "report"]

    if not units:
        if sources:  # scope registry may list the target without a targets/ dir
            fb = sources.get("fallback") or {}
            merged["state"] = sources.get("state", "unknown")
            for name in aspects_in_order:
                st = fb.get(name)
                merged.setdefault(name, {
                    "status": st if st in ("failed",) else NOT_RUN,
                    "reason": "no execution artifacts found"})
                merged[name]["dir"] = None
        for name in aspects_in_order:
            merged.setdefault(name, {"status": NOT_RUN, "reason": "no execution artifacts found"})
        return merged

    for name in aspects_in_order:
        cands = []
        for u in units:
            ev = read_evidence_unit(u["unit"], key, u["fallback"])
            cands.append(ev.get(name, {"status": NOT_RUN}))
        if cands:
            best = cands[0]
            for c in cands[1:]:
                best = _better(best, c)
            merged[name] = best
        else:
            merged[name] = {"status": NOT_RUN}

    # target state from the authoritative registry where available
    state = "pending"
    reason = ""
    if kind == "scope":
        for scope in list_scopes(manifest, adir, kind):
            if target not in ((scope.get("scope") or {}).get("targets") or []):
                continue
            reg_path = os.path.join(scope["dir"], "registry", "%s.json" % key)
            if os.path.isfile(reg_path):
                try:
                    with open(reg_path, "r", encoding="utf-8") as fh:
                        reg = json.load(fh)
                except Exception:
                    continue
                st = str(reg.get("state") or "pending")
                if PREFERENCE.get(st, 9) <= PREFERENCE.get(state, 9):
                    state = st
                reason = reason or str(reg.get("reason") or "")
    elif kind == "single":
        phase = manifest.get("current_phase") or ""
        state = "completed" if (manifest.get("status") == "completed") else \
            ("failed" if (manifest.get("status") == "failed") else "in_progress")
    merged["state"] = state
    merged["state_reason"] = reason
    return merged


def collect_all_targets(root, aid):
    manifest, kind = load_manifest(root, aid)
    adir = assessment_dir(root, aid)
    targets = list_targets(manifest, adir, kind)
    out = {}
    for t in targets:
        out[safe_name(t)] = collect_target_evidence(root, aid, t)
    return manifest, kind, out