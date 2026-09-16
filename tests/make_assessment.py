#!/usr/bin/env python3
#
# tests/make_assessment.py - deterministic synthetic assessment generator used
# by the Phase 12 (history / comparison) test matrix.
#
# Usage:
#   python3 tests/make_assessment.py <root> <kind> <aid> <options...>
#
#   <root>    assessments root directory (created if missing)
#   <kind>    single | scope | corrupt
#   <aid>     assessment id (must start with "assessment_")
#
# Options (single / scope):
#   --target <t>            single: one target string  (default 203.0.113.7)
#   --targets <a,b,...>     scope: target list          (default 203.0.113.7,203.0.113.8)
#   --state <s>             discovery host state: up | down | no-artifact
#   --ports <csv>           open ports for enumeration (e.g. 21/tcp:vsftpd:2.3.4,80/tcp:http)
#   --service <csv>         same len as --ports: service name per fixed port list
#   --candidates <csv>      exploitdb candidate ids for exploitation (e.g. 17491,17546)
#   --correlate <csv>       correlated exploit ids (subset that produced findings)
#   --session               create exploitation evidence + a live evidence session
#   --options <json>        extra key=value to fold into result.txt copies
#   --phases <csv>          phases declared completed in the manifest
#   --failed <csv>          phases declared failed in the manifest
#   --status <s>            manifest status (default completed)
#   --seed <n>              deterministic RNG seed (default 1)
#
# <kind> == corrupt: creates <aid> with a corrupt manifest.json (the reader
#                    must refuse to fabricate state from it).
#
# Exit code: 0 on success, 1 on usage or generator fault. The generator is
# production-fixture code, not a fake tool: it never fabricates RECORDED
# artifacts when marks are corrupt or its own tree is inconsistent (it fails
# loudly instead).

import json
import os
import random
import re
import sys
from datetime import datetime, timezone

SAFE = re.compile(r"[^A-Za-z0-9_.-]")


def safe_name(text):
    return SAFE.sub("_", str(text or ""))


def ts_for(idx):
    """Deterministic ascending artifact timestamps (lexicographic ==
    chronological, matching the real scanner's epoch-named artifacts)."""
    base = datetime(2028, 5, 3, 9, 15, 30, tzinfo=timezone.utc)
    return (base.replace(second=base.second + idx)).strftime("%Y%m%d_%H%M%S")


def write(path, text):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.write("\n")


def kv_txt(items):
    return "\n".join("%s=%s" % (k, v) for k, v in items.items())


def tsv(header, rows):
    lines = ["\t".join(header)]
    for r in rows:
        lines.append("\t".join(str(x) for x in r))
    return "\n".join(lines)


DEFAULT_PHASES = ["discovery", "enumeration", "vulnerabilities", "correlation",
                  "exploitation", "evidence", "report"]


def default_ports():
    return [
        {"port": "21", "proto": "tcp", "service": "ftp", "product": "vsftpd",
         "version": "2.3.4", "extrainfo": "", "cpe": ""},
        {"port": "80", "proto": "tcp", "service": "http", "product": "Apache",
         "version": "2.2.8", "extrainfo": "", "cpe": ""},
    ]


def default_candidates():
    return [
        {"edb_id": "17491", "title": "vsftpd 2.3.4 - Backdoor Command Execution",
         "service": "ftp", "product": "vsftpd", "version": "2.3.4"},
        {"edb_id": "17546", "title": "Apache 2.2.8 mod_cgi - arbitrary execution",
         "service": "http", "product": "Apache", "version": "2.2.8"},
    ]


# ------------------------------------------------------------------
# Phase artifact writers
# ------------------------------------------------------------------

def write_discovery(unit, prefix, ts, state):
    """discovery/ : single .txt host check or nmap xml; host state is what
    discovery actually observed (up / down). No artifact => not-run."""
    od = os.path.join(unit, "discovery")
    if state not in ("up", "down"):
        return  # no artifact = discovery not-run
    txt = os.path.join(od, "%s_%s_discovery.txt" % (prefix, ts))
    if state == "up":
        write(txt, "Starting scanner at %s\nHost is up (0.0012s latency).\n" % ts)
    else:
        write(txt, "Starting scanner at %s\nNo response (host down).\n" % ts)


def write_enumeration(unit, prefix, ts, ports, rng):
    """enumeration/ : one nmap XML with open ports (parse_xml_ports reads it).
    ports == [] and no_html -> a services .txt that the reader maps to
    "no open ports" when present."""
    od = os.path.join(unit, "enumeration")
    if ports is None:
        return  # not-run
    if not ports:
        txt = os.path.join(od, "%s_%s_enum.txt" % (prefix, ts))
        write(txt, "No open ports found on the target during enumeration scan.\n")
        return
    x = ["<?xml version='1.0' encoding='UTF-8'?>",
         "<nmaprun>",
         " <host>",
         "  <status state='up'/>",
         "  <ports>"]
    for p in ports:
        x.append("   <port protocol='%s' portid='%s'>"
                 % (p.get("proto", "tcp"), p.get("port", "")))
        x.append("    <state state='open'/>")
        x.append("    <service name='%s' product='%s' version='%s' extrainfo='%s'/>"
                 % (p.get("service", ""), p.get("product", ""),
                    p.get("version", ""), p.get("extrainfo", "")))
        x.append("   </port>")
    x.append("  </ports>")
    x.append(" </host>")
    x.append("</nmaprun>")
    write(os.path.join(od, "%s_%s_enum.xml" % (prefix, ts)), "\n".join(x))


def write_vulnerabilities(unit, prefix, ts, candidates, rng):
    """vulnerabilities/ : services.tsv + exploitdb_candidates.tsv (candidate
    research phase; select into correlation later)."""
    if candidates is None:
        return
    vdir = os.path.join(unit, "vulnerabilities", "%s_%s_research" % (prefix, ts))
    rows = []
    for c in candidates:
        rows.append((c.get("service", ""), c.get("port", ""), c.get("product", ""),
                     c.get("version", ""), c.get("edb_id", ""), c.get("title", "")))
    write(os.path.join(vdir, "services.tsv"),
          tsv(["service", "port", "product", "version", "edb_id", "title"], rows))
    cand_rows = []
    for c in candidates:
        cand_rows.append((c.get("edb_id", ""), "%s %s %s" % (
            c.get("service", ""), c.get("product", ""), c.get("version", ""))
            if c.get("service") else "", c.get("title", "")))
    write(os.path.join(vdir, "exploitdb_candidates.tsv"),
          tsv(["edb_id", "service", "title"], cand_rows))
    write(os.path.join(vdir, "status.txt"), kv_txt({"status": "completed"}))


def write_correlation(unit, prefix, ts, correlated, rng):
    """correlation/ : correlated_findings.tsv for findings actually
    correlated (subset of candidates)."""
    if correlated is None:
        return
    cdir = os.path.join(unit, "correlation", "%s_%s_correlation" % (prefix, ts))
    rows = []
    for c in correlated:
        rows.append(("high", c.get("product", ""), c.get("version", ""),
                     c.get("port", ""), c.get("edb_id", ""), c.get("title", "")))
    write(os.path.join(cdir, "correlated_findings.tsv"),
          tsv(["severity", "product", "version", "port", "exploit_id", "title"], rows))
    write(os.path.join(cdir, "status.txt"), kv_txt({"status": "completed"}))


def write_exploitation(unit, prefix, ts, candidates, make_session, rng):
    """exploitation/ : result.txt + status.txt. When make_session the worker
    produced a real session id and a matching evidence/ session record."""
    if candidates is None:
        return
    xdir = os.path.join(unit, "exploitation", "%s_%s_exploit" % (prefix, ts))
    if make_session:
        result = {
            "session_status": "session-created",
            "session_id": "%s_%s" % (safe_name(ts), rng.randint(1, 9999)),
            "session_type": "meterpreter",
            "selected_module": "exploit/unix/ftp/vsftpd_234_backdoor",
            "candidate_title": (candidates[0] or {}).get("title", ""),
            "approval": "approved",
        }
    else:
        result = {
            "session_status": "no-session",
            "approval": "denied",
            "selected_module": "",
            "candidate_title": "",
        }
    write(os.path.join(xdir, "result.txt"), kv_txt(result))
    write(os.path.join(xdir, "status.txt"), kv_txt({"status": result["session_status"]}))


def write_evidence(unit, prefix, ts, make_session, rng):
    """evidence/ : where a real session was created the evidence module
    recorded session.txt + session_status (Phase 9 evidence view)."""
    edir = os.path.join(unit, "evidence", "%s_%s_evidence" % (prefix, ts))
    if make_session:
        write(os.path.join(edir, "session.txt"),
              kv_txt({"session_id": "s-1", "session_name": "meterpreter 1",
                      "session_status": "active", "session_type": "meterpreter"}))
        write(os.path.join(edir, "status.txt"),
              kv_txt({"status": "session-created"}))
    else:
        write(os.path.join(edir, "status.txt"),
              kv_txt({"status": "no-session", "reason": "no active session to record"}))


def write_report(unit, prefix, ts):
    rdir = os.path.join(unit, "report", "%s_%s.md" % (prefix, ts))
    write(rdir, "# Assessment report\n\nTarget: %s\n\nSee report/ for the full report.\n" % prefix)


# ------------------------------------------------------------------
# Assessment writers
# ------------------------------------------------------------------

def build_single(root, aid, opts, rng):
    adir = os.path.join(root, aid)
    target = opts.get("target", "203.0.113.7")
    prefix = safe_name(target)
    ts = ts_for(0)

    status = opts.get("status", "completed")
    phases = (opts.get("phases") or DEFAULT_PHASES)[:]
    failed = (opts.get("failed") or [])[:]
    up = opts.get("state", "up")
    ports = opts.get("ports", None)
    if ports is None:
        ports = default_ports() if status == "completed" else []
    candidates = opts.get("candidates", None)
    if candidates is None:
        candidates = default_candidates()
    correlated = opts.get("correlate", None)
    session = opts.get("session", False)

    # manifest (historical state; the reader trusts only what is here)
    manifest = {
        "assessment_id": aid,
        "target": target,
        "started_at": "2028-05-03T09:15:00+0000",
        "updated_at": "2028-05-03T09:30:00+0000",
        "status": status,
        "current_phase": phases[-1] if phases else "",
        "completed_phases": phases,
        "failed_phases": failed,
    }
    write(os.path.join(adir, "manifest.json"), json.dumps(manifest, indent=2))

    write_discovery(adir, prefix, ts, up)
    write_enumeration(adir, prefix, ts, ports, rng)
    if up == "up" and ports:
        write_vulnerabilities(adir, prefix, ts, candidates, rng)
        if correlated is not None:
            write_correlation(adir, prefix, ts, correlated, rng)
        write_exploitation(adir, prefix, ts, candidates, session, rng)
    write_evidence(adir, prefix, ts, session, rng)
    write_report(adir, prefix, ts)
    return adir


def build_scope(root, aid, opts, rng):
    adir = os.path.join(root, aid)
    targets = (opts.get("targets") or ["203.0.113.7", "203.0.113.8"])
    status = opts.get("status", "completed")
    phases = (opts.get("phases") or DEFAULT_PHASES)[:]
    failed = (opts.get("failed") or [])[:]

    watch = [t for t in targets if t not in failed]  # scope-based never completes failed targets
    manifest = {
        "assessment_id": aid,
        "target": "",
        "scope_based": True,
        "started_at": "2028-05-03T09:15:00+0000",
        "updated_at": "2028-05-03T09:30:00+0000",
        "status": status,
        "current_phase": phases[-1] if phases else "",
        "completed_phases": phases,
        "failed_phases": failed,
    }
    write(os.path.join(adir, "manifest.json"), json.dumps(manifest, indent=2))

    base_ts = ts_for(len(targets))
    for i, t in enumerate(targets):
        prefix = safe_name(t)
        sid = "scope_%d" % (i + 1)
        ts = ts_for(i)
        sroot = os.path.join(adir, "scopes", sid)
        scope = {
            "scope_id": sid,
            "assessment_id": aid,
            "status": "completed" if t not in failed else "pending",
            "scope": {"name": "Synthetic scope %d" % (i + 1),
                      "type": "host",
                      "state": "completed" if t not in failed else "pending",
                      "targets": [t], "target_count": 1},
        }
        unit = os.path.join(sroot, "targets", prefix)
        write(os.path.join(sroot, "scope.json"), json.dumps(scope, indent=2))
        # per-target registry (authoritative phase state fallback)
        reg = {"scope_id": sid, "target": t, "state": "completed",
               "phases": {"discovery": "completed", "enumeration": "completed",
                          "vulnerabilities": "completed", "correlation": "completed",
                          "exploitation": "completed", "evidence": "completed"}}
        if t in failed:
            reg["state"] = "failed"
            reg["phases"] = {"discovery": "failed", "enumeration": "not-run",
                             "vulnerabilities": "not-run", "correlation": "not-run",
                             "exploitation": "not-run", "evidence": "not-run"}
        write(os.path.join(sroot, "registry", "%s.json" % prefix), json.dumps(reg, indent=2))

        write_discovery(unit, prefix, ts, "up" if t not in failed else None)
        write_enumeration(unit, prefix, ts, default_ports() if t not in failed else [], rng)
        if t not in failed:
            write_vulnerabilities(unit, prefix, ts, default_candidates(), rng)
            write_correlation(unit, prefix, ts, default_candidates(), rng)
            write_exploitation(unit, prefix, ts, default_candidates(), True, rng)
            write_evidence(unit, prefix, ts, True, rng)
        write_report(unit, prefix, ts)
    return adir


def build_corrupt(root, aid, opts, rng):
    adir = os.path.join(root, aid)
    os.makedirs(adir, exist_ok=True)
    write(os.path.join(adir, "manifest.json"), "{ this is not valid json")
    return adir


# ------------------------------------------------------------------
# main
# ------------------------------------------------------------------

def parse_opt(list_):
    opts = {"ports": None, "candidates": None, "correlate": None}
    i = 0
    while i < len(list_):
        k = list_[i]
        i += 1
        if k == "--target":
            opts["target"] = list_[i]; i += 1
        elif k == "--targets":
            opts["targets"] = [x.strip() for x in list_[i].split(",") if x.strip()]
            i += 1
        elif k == "--state":
            opts["state"] = list_[i]; i += 1
        elif k == "--ports":
            ports = []
            for rec in list_[i].split(","):
                if not rec.strip():
                    continue
                parts = [x.strip() for x in rec.split(":")]
                ports.append({"port": parts[0] if len(parts) > 0 else "",
                              "proto": parts[1] if len(parts) > 1 else "tcp",
                              "service": parts[2] if len(parts) > 2 else "",
                              "product": parts[3] if len(parts) > 3 else "",
                              "version": parts[4] if len(parts) > 4 else "",
                              "extrainfo": None})
            opts["ports"] = ports
            i += 1
        elif k == "--candidates":
            opts["candidates"] = []
            for c in list_[i].split(","):
                if not c.strip():
                    continue
                rec = {"edb_id": c.strip(), "title": "candidate %s" % c.strip(),
                       "service": "http", "product": "Apache", "version": "2.2.8",
                       "port": "80"}
                opts["candidates"].append(rec)
            i += 1
        elif k == "--correlate":
            opts["correlate"] = [{"edb_id": c.strip(), "title": "correlated %s" % c.strip(),
                                  "service": "http", "product": "Apache",
                                  "version": "2.2.8", "port": "80"}
                                 for c in list_[i].split(",") if c.strip()]
            i += 1
        elif k == "--session":
            opts["session"] = True
        elif k == "--phases":
            opts["phases"] = [x.strip() for x in list_[i].split(",") if x.strip()]
            i += 1
        elif k == "--failed":
            opts["failed"] = [x.strip() for x in list_[i].split(",") if x.strip()]
            i += 1
        elif k == "--status":
            opts["status"] = list_[i]; i += 1
        elif k == "--seed":
            opts["seed"] = int(list_[i]); i += 1
        else:
            sys.stderr.write("[-] Unknown option: %s\n" % k)
            sys.exit(1)
    return opts


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(
            "Usage: %s <root> <kind> <aid> [options...]\n" % os.path.basename(argv[0]))
        return 1
    root, kind, aid = argv[1:4]
    if not aid.startswith("assessment_"):
        sys.stderr.write("[-] invalid assessment id: %s (must start with 'assessment_')\n" % aid)
        return 1
    opts = parse_opt(argv[4:])
    rng = random.Random(opts.get("seed", 1))
    try:
        if kind == "single":
            build_single(root, aid, opts, rng)
        elif kind == "scope":
            build_scope(root, aid, opts, rng)
        elif kind == "corrupt":
            build_corrupt(root, aid, opts, rng)
        else:
            sys.stderr.write("[-] unknown kind: %s (single|scope|corrupt)\n" % kind)
            return 1
    except OSError as exc:
        sys.stderr.write("[-] generator fault: %s\n" % exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
