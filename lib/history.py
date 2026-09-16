#!/usr/bin/env python3
#
# history <assessment_id> - detailed, read-only historical view (Phase 12).
#
# Usage:
#   python3 lib/history.py <assessments_root> <assessment_id>
#
# This is a pure READ operation. It never rewrites an assessment, never
# deletes artifacts Board, and never fabricates state that is not on disk.
#
# Output (stdout) is a structured, terminal-friendly per-target detail view:
#   Assessment ID
#   Scope ID (scope-based assessments) or (single-target, no scope)
#   Target count
#   Assessment status
#   Started timestamp
#   Completed timestamp if available
#   Current/last phase
#   Completed phases
#   Failed phases
#   Per-target:
#     target identity / key
#     target state
#     per-phase state + concise evidence (ports/services/versions/findings/
#       correlated findings/exploit attempts/sessions)
#     artifact paths for each phase (evidence references)
#
# Exit codes:
#   0  detail shown
#   1  usage/technical error, unknown/corrupt assessment, missing manifest
#
# The detail view refuses to fabricate: a corrupt/missing manifest, an
# unknown assessment id, or a malformed registry are clean errors.

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import target_evidence as te  # noqa: E402


def safe_ts(name):
    m = re.search(r"(\d{8}_\d{6}(?:_\d+)?)", name or "")
    return m.group(1) if m else (name or "")


def list_phase_dirs(unit, phase, prefix):
    base = os.path.join(unit, phase)
    if not os.path.isdir(base):
        return []
    return sorted(d for d in
                  (os.path.join(base, n) for n in os.listdir(base))
                  if os.path.isdir(d) and
                  os.path.basename(d).startswith(prefix + "_"))


def latest_matching(adir, pattern, directories=True):
    if not os.path.isdir(adir):
        return None
    found = []
    if directories:
        found = [d for d in
                 (os.path.join(adir, n) for n in os.listdir(adir))
                 if os.path.isdir(d) and
                 re.match(pattern, os.path.basename(d))]
    elif os.path.isdir(adir):
        found = [f for f in
                 (os.path.join(adir, n) for n in os.listdir(adir))
                 if os.path.isfile(f) and
                 re.match(pattern, os.path.basename(f))]
    if not found:
        return None
    return sorted(found)[-1]


def kv_items(path):
    out = {}
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


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(text or ""))


def assessment_id(adir):
    return os.path.basename(adir)


def show_detail(root, aid):
    manifest, kind = te.load_manifest(root, aid)
    adir = te.assessment_dir(root, aid)
    scopes = te.list_scopes(manifest, adir, kind)
    targets = te.list_targets(manifest, adir, kind)

    print()
    print("[+] Assessment: %s" % aid)
    print()
    if kind == "scope":
        print("    scope-based      : yes")
        print("    scopes           : %d" % len(scopes))
        for sc in scopes:
            s = sc.get("scope") or {}
            print("      %s  name=%s  type=%s  status=%s  targets=%s"
                  % (sc.get("id") or "?",
                     s.get("name") or "-",
                     s.get("type") or "-",
                     s.get("status") or "-",
                     len(s.get("targets") or [])))
    else:
        print("    scope-based      : no (single-target layout)")
        print("    scopes           : 0")
    print("    targets          : %d" % len(targets))
    print("    status           : %s" % (manifest.get("status") or "-"))
    print("    started_at       : %s" % (manifest.get("started_at") or "-"))
    if manifest.get("status") == "completed":
        print("    completed_at     : %s" % (manifest.get("updated_at") or manifest.get("started_at") or "-"))
    else:
        print("    completed_at     : -")
    print("    current_phase    : %s" % (manifest.get("current_phase") or "-"))
    print("    completed_phases : %s"
          % (", ".join(manifest.get("completed_phases") or []) or "-"))
    print("    failed_phases    : %s"
          % (", ".join(manifest.get("failed_phases") or []) or "-"))
    if kind == "scope":
        print("    scopes           : %d" % len(scopes))
        for sc in scopes:
            s = sc.get("scope") or {}
            print("      %s  name=%s  type=%s  status=%s  targets=%s"
                  % (sc.get("id") or "?",
                     s.get("name") or "-",
                     s.get("type") or "-",
                     s.get("status") or "-",
                     len(s.get("targets") or [])))
    print()

    if not targets:
        if kind == "scope" and scopes:
            print("    [-][!] Scope-based but no readable target records found.")
            print("           Historical record is incomplete; refusing to fabricate")
            print("           per-target detail. Scopes above are listed as recorded.")
        else:
            print("    [-][!] No target recorded for this assessment.")
        return 0

    for t in targets:
        print("    ------------------------------------------------------")
        print("    Target: %s" % t)
        print()
        ev = te.collect_target_evidence(root, aid, t)
        key = ev.get("key") or safe_name(t)
        print("        key (stable identity) : %s" % key)
        if ev.get("state"):
            print("        target state          : %s" % ev["state"])
            if ev.get("state_reason"):
                print("        state reason          : %s" % ev["state_reason"])
        if ev.get("scopes"):
            print("        scopes                : %s" % ", ".join(ev["scopes"]))

        # discovery
        d = ev.get("discovery") or {}
        st = d.get("status") or "not-run"
        up = d.get("up")
        if st == "completed":
            print("        discovery             : completed (host %s)" % ("up" if up is True else "down" if up is False else "unknown"))
        else:
            print("        discovery             : %s%s"
                  % (st, (" (%s)" % d.get("reason")) if d.get("reason") else ""))
        if d.get("artifact"):
            print("            artifact        : %s" % d["artifact"])

        # enumeration
        e = ev.get("enumeration") or {}
        st = e.get("status") or "not-run"
        if st == "completed":
            ports = e.get("ports") or []
            if e.get("no_open_ports"):
                print("        enumeration           : completed (no open ports)")
            else:
                print("        enumeration           : completed (%d open port(s))" % len(ports))
            for p in ports:
                svc = " ".join(x for x in (p.get("service"), p.get("product"),
                                           p.get("version")) if x)
                print("            %-6s %-4s %s"
                      % (p.get("port"), p.get("protocol") or "tcp", svc or "-"))
        else:
            print("        enumeration           : %s%s"
                  % (st, (" (%s)" % e.get("reason")) if e.get("reason") else ""))
        if e.get("artifact"):
            print("            artifact        : %s" % e["artifact"])

        # vulnerabilities (research)
        v = ev.get("vulnerabilities") or {}
        st = v.get("status") or "not-run"
        if st == "completed":
            cands = v.get("candidates") or []
            print("        vulnerabilities       : completed (%d candidate(s))" % len(cands))
            for i, c in enumerate(cands, 1):
                comp = " ".join(x for x in (c.get("service"), c.get("product"),
                                            c.get("version")) if x)
                print("            [%d] EDB-%s  %s  %s"
                      % (i, c.get("edb_id") or "-", comp or "-",
                         c.get("title") or "-"))
        else:
            print("        vulnerabilities       : %s%s"
                  % (st, (" (%s)" % v.get("reason")) if v.get("reason") else ""))
        if v.get("artifact"):
            print("            artifact        : %s" % v["artifact"])

        # correlation
        c = ev.get("correlation") or {}
        st = c.get("status") or "not-run"
        if st == "completed":
            findings = c.get("findings") or []
            print("        correlation           : completed (%d finding(s))" % len(findings))
            for f in findings:
                print("            [%s] %s %s %s %s"
                      % (f.get("severity") or "?",
                         f.get("product") or "-",
                         f.get("detected_version") or "-",
                         f.get("port") or "-",
                         f.get("correlated_exploit") or f.get("title") or "-"))
        else:
            print("        correlation           : %s%s"
                  % (st, (" (%s)" % c.get("reason")) if c.get("reason") else ""))
        if c.get("artifact"):
            print("            artifact        : %s" % c["artifact"])

        # exploitation
        x = ev.get("exploitation") or {}
        st = x.get("status") or "not-run"
        print("        exploitation          : %s" % st)
        if x.get("selected_module"):
            print("            module           : %s" % x["selected_module"])
        if x.get("session_id"):
            print("            session          : %s (id %s)"
                  % (x.get("session_type") or "-", x["session_id"]))
        if x.get("reason"):
            print("            reason           : %s" % x["reason"])
        if x.get("artifact"):
            print("            artifact        : %s" % x["artifact"])

        # evidence
        w = ev.get("evidence") or {}
        st = w.get("status") or "not-run"
        print("        evidence              : %s" % st)
        if w.get("session_id"):
            print("            session          : %s (id %s)"
                  % (w.get("session_type") or "-", w["session_id"]))
        if w.get("reason"):
            print("            reason           : %s" % w["reason"])
        if w.get("artifact"):
            print("            artifact        : %s" % w["artifact"])

        # report
        r = ev.get("report") or {}
        if r.get("artifact"):
            print("        report                : present")
            print("            artifact        : %s" % r["artifact"])

        # raw summary line (unified per-aspect status)
        print()
        print("        aspects: %s"
              % " | ".join(
                  "%s=%s" % (a, (ev.get(a) or {}).get("status") or "not-run")
                  for a in ("discovery", "enumeration", "vulnerabilities",
                            "correlation", "exploitation", "evidence")))
        print()

    print("    ------------------------------------------------------")
    return 0


def main(argv):
    if len(sys.argv) != 3:
        print("Usage: %s <assessments_root> <assessment_id>" % os.path.basename(sys.argv[0]),
              file=sys.stderr)
        return 1
    root, aid = sys.argv[1:3]
    try:
        show_detail(root, aid)
    except te.EvidenceError as exc:
        print("[-] %s" % exc, file=sys.stderr)
        return 1
    except OSError as exc:
        print("[-] Could not read historical data: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
