#!/usr/bin/env python3
#
# compare <assessment_A> <assessment_B> - evidence-aware, read-only
# historical comparison (Phase 12).
#
# Usage:
#   lib/comparison.py <assessments_root> <assessment_A> <assessment_B> <out_dir>
#
# Matches targets by STABLE TARGET IDENTITY (the target string), never by
# scope membership. Classification is evidence-driven:
#
#   NEW            reliable evidence in B, none in A
#   REMOVED        reliable evidence of actual disappearance (complete scans)
#   CHANGED        same identity, reliable evidence differs
#   UNCHANGED      comparable evidence present in BOTH and identical
#   UNKNOWN        evidence missing/failed/interrupted/dependency missing
#   NOT_COMPARABLE records exist but cannot legitimately be compared
#
# Invariants enforced here:
#   FAILED != NOT OBSERVED            (a failure is never treated as absence)
#   DEPENDENCY MISSING != REMOVED     (findings are never erased by a later
#                                     dependency failure)
#   NO EVIDENCE != NEGATIVE EVIDENCE  (missing artifacts never imply the thing
#                                     does not exist)
#   HISTORY IS READ-ONLY              (this tool never modifies an assessment)
#
# Terminal output + a machine-readable comparison artifact are both written.
# The artifact lives in a NEW per-run directory (never inside the historical
# assessments) using the project's per-run directory convention.

import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import target_evidence as te  # noqa: E402

NEW = "NEW"
REMOVED = "REMOVED"
CHANGED = "CHANGED"
UNCHANGED = "UNCHANGED"
UNKNOWN = "UNKNOWN"
NOT_COMPARABLE = "NOT_COMPARABLE"

CLASSES = (NEW, REMOVED, CHANGED, UNCHANGED, UNKNOWN, NOT_COMPARABLE)

RELIABLE_EXPLOIT = ("session-created", "no-session")


def norm(text):
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def portnum_int(p):
    try:
        return int(p.get("port") or 0)
    except (TypeError, ValueError):
        return 0


def service_sig(p):
    return (norm(p.get("product")), norm(p.get("version")), norm(p.get("service")))


def candidate_key(c):
    edb = norm(c.get("edb_id"))
    title = norm(c.get("exploit_title") or c.get("title"))
    return (edb, title)


def reliable_present(ev):
    """A target in an assessment counts as NEW-eligible only when the later
    side actually observed it (any completed phase)."""
    for name in ("discovery", "enumeration", "vulnerabilities", "correlation"):
        if (ev.get(name) or {}).get("status") == "completed":
            return True
    return False


# ------------------------------------------------------------------
# Aspect comparisons
# ------------------------------------------------------------------

def compare_discovery(evA, evB):
    da = evA.get("discovery") or {}
    db = evB.get("discovery") or {}
    a_up = da.get("up")
    b_up = db.get("up")
    a_ok = da.get("status") == "completed" and a_up is not None
    b_ok = db.get("status") == "completed" and b_up is not None
    if not (a_ok and b_ok):
        reasons = []
        if not a_ok:
            reasons.append("A discovery %s" % (da.get("status") or "not-run"))
        if not b_ok:
            reasons.append("B discovery %s" % (db.get("status") or "not-run"))
        return {"aspect": "discovery", "classification": UNKNOWN,
                "a": "up" if a_up is True else "down" if a_up is False else "unknown",
                "b": "up" if b_up is True else "down" if b_up is False else "unknown",
                "reason": ", ".join(reasons)}
    if a_up is False and b_up is False:
        return {"aspect": "discovery", "classification": UNCHANGED,
                "a": "down", "b": "down", "hosts_up": False}
    if a_up is True and b_up is False:
        return {"aspect": "discovery", "classification": REMOVED,
                "a": "up", "b": "down",
                "reason": "host observed up in A and down in B with complete discovery evidence"}
    if a_up is False and b_up is True:
        return {"aspect": "discovery", "classification": CHANGED,
                "a": "down", "b": "up",
                "reason": "host observed down in A and up in B"}
    return {"aspect": "discovery", "classification": UNCHANGED, "a": "up", "b": "up"}


def compare_ports(evA, evB):
    ea = evA.get("enumeration") or {}
    eb = evB.get("enumeration") or {}
    rel_a = ea.get("status") == "completed"
    rel_b = eb.get("status") == "completed"

    def port_map(ev):
        return {portnum_int(p): p for p in (ev.get("ports") or [])}

    pa = port_map(evA) if rel_a else {}
    pb = port_map(evB) if rel_b else {}

    all_nums = sorted(set(pa) | set(pb))
    comparisons = []

    if not (rel_a and rel_b):
        # Not both enumerations are reliable: no removal/no-new may be inferred.
        reasons = []
        if not rel_a:
            reasons.append("A enumeration %s" % (ea.get("status") or "not-run"))
        if not rel_b:
            reasons.append("B enumeration %s" % (eb.get("status") or "not-run"))
        changed_any = False
        for pn in all_nums:
            comparisons.append({"port": str(pn), "protocol": "-",
                                "classification": UNKNOWN,
                                "reason": ", ".join(reasons),
                                "service_a": None, "service_b": None})
        return {"aspect": "ports", "classification": UNKNOWN,
                "reliable_a": rel_a, "reliable_b": rel_b,
                "comparisons": comparisons,
                "reason": ", ".join(reasons), "changed": False}

    changed_any = False
    for pn in all_nums:
        pa_rec = pa.get(pn)
        pb_rec = pb.get(pn)
        if pa_rec and pb_rec:
            proto_a = pa_rec.get("protocol", "tcp")
            proto_b = pb_rec.get("protocol", "tcp")
            if proto_a != proto_b:
                changed_any = True
                comparisons.append({"port": str(pn), "protocol": "-",
                                    "classification": NOT_COMPARABLE,
                                    "reason": "protocol differs: A=%s B=%s"
                                              % (proto_a, proto_b),
                                    "service_a": None, "service_b": None})
                continue
            sig_a = service_sig(pa_rec)
            sig_b = service_sig(pb_rec)
            known_a = any(sig_a)
            known_b = any(sig_b)
            proto = proto_a
            if not (known_a and known_b):
                comparisons.append({"port": str(pn), "protocol": proto,
                                    "classification": UNKNOWN,
                                    "reason": "service not reliably identified on one side",
                                    "service_a": " ".join(x for x in (pa_rec.get("product"), pa_rec.get("version"), pa_rec.get("service")) if x) or None,
                                    "service_b": " ".join(x for x in (pb_rec.get("product"), pb_rec.get("version"), pb_rec.get("service")) if x) or None})
                continue
            if sig_a == sig_b:
                comparisons.append({"port": str(pn), "protocol": proto,
                                    "classification": UNCHANGED,
                                    "service_a": " ".join(x for x in (pa_rec.get("product"), pa_rec.get("version"), pa_rec.get("service")) if x),
                                    "service_b": " ".join(x for x in (pb_rec.get("product"), pb_rec.get("version"), pb_rec.get("service")) if x)})
                continue
            # different: product change or version change
            if norm(pa_rec.get("product")) != norm(pb_rec.get("product")):
                cls = CHANGED
                reason = "product changed"
            elif norm(pa_rec.get("version")) and norm(pb_rec.get("version")) \
                    and norm(pa_rec.get("version")) != norm(pb_rec.get("version")):
                cls = CHANGED
                reason = "version changed"
            else:
                # same product, version evidence missing on one side
                cls = UNKNOWN
                reason = "version evidence missing on one side (no change inferred)"
            if cls == CHANGED:
                changed_any = True
            comparisons.append({"port": str(pn), "protocol": proto,
                                "classification": cls, "reason": reason,
                                "service_a": " ".join(x for x in (pa_rec.get("product"), pa_rec.get("version"), pa_rec.get("service")) if x),
                                "service_b": " ".join(x for x in (pb_rec.get("product"), pb_rec.get("version"), pb_rec.get("service")) if x)})
        elif pa_rec:  # in A only, both enumerations reliable -> REMOVED
            changed_any = True
            comparisons.append({"port": str(pn),
                                "protocol": pa_rec.get("protocol", "tcp"),
                                "classification": REMOVED,
                                "reason": "open in A, not observed open in complete B scan",
                                "service_a": " ".join(x for x in (pa_rec.get("product"), pa_rec.get("version"), pa_rec.get("service")) if x) or None,
                                "service_b": None})
        else:  # in B only, both reliable -> NEW
            changed_any = True
            comparisons.append({"port": str(pn),
                                "protocol": pb_rec.get("protocol", "tcp"),
                                "classification": NEW,
                                "reason": "open in complete B scan, absent in A",
                                "service_a": None,
                                "service_b": " ".join(x for x in (pb_rec.get("product"), pb_rec.get("version"), pb_rec.get("service")) if x) or None})

    overall = CHANGED if changed_any else UNCHANGED
    return {"aspect": "ports", "classification": overall,
            "reliable_a": rel_a, "reliable_b": rel_b,
            "comparisons": comparisons, "changed": changed_any}


def compare_research(evA, evB):
    ra = evA.get("vulnerabilities") or {}
    rb = evB.get("vulnerabilities") or {}
    a_st = ra.get("status") or "not-run"
    b_st = rb.get("status") or "not-run"
    if a_st == b_st == "not-run":
        return None  # research not applicable to either assessment
    if a_st == "completed" and b_st == "completed":
        ca = {candidate_key(c): c for c in (ra.get("candidates") or [])}
        cb = {candidate_key(c): c for c in (rb.get("candidates") or [])}
        items = []
        changed = False
        for key in sorted(set(ca) | set(cb)):
            if key in ca and key in cb:
                items.append({"id": (key[0] or key[1] or "-"), "classification": UNCHANGED})
            elif key in ca:
                changed = True
                items.append({"id": (key[0] or key[1] or "-"), "classification": REMOVED,
                              "reason": "candidate absent from B (A and B research both completed)"})
            else:
                changed = True
                items.append({"id": (key[0] or key[1] or "-"), "classification": NEW})
        return {"aspect": "research", "classification": CHANGED if changed else UNCHANGED,
                "a": "%d candidate(s)" % len(ca), "b": "%d candidate(s)" % len(cb),
                "items": items}
    # At least one side has research evidence but they are not both reliably
    # comparable -> UNKNOWN (dependency-missing and failed included).
    reasons = []
    for side, st, rec in (("A", a_st, ra), ("B", b_st, rb)):
        if st == "completed":
            reasons.append("%s completed" % side)
        elif st == "dependency-missing":
            reasons.append("%s dependency-missing (%s)" % (side, rec.get("reason") or "?"))
        elif st == "failed":
            reasons.append("%s failed" % side)
        else:
            reasons.append("%s not-run" % side)
    return {"aspect": "research", "classification": UNKNOWN,
            "a": a_st, "b": b_st, "reason": "; ".join(reasons)}


def compare_correlation(evA, evB):
    ca = evA.get("correlation") or {}
    cb = evB.get("correlation") or {}
    a_st = ca.get("status") or "not-run"
    b_st = cb.get("status") or "not-run"

    # correlation is applicable when research evidence exists on either side
    applied = False
    for ev, st in ((evA, a_st), (evB, b_st)):
        research = (ev.get("vulnerabilities") or {}).get("status")
        if research == "completed" or st != "not-run":
            applied = True
    if not applied:
        return None

    if a_st == "completed" and b_st == "completed":
        fa = {candidate_key(f): f for f in (ca.get("findings") or [])}
        fb = {candidate_key(f): f for f in (cb.get("findings") or [])}
        items = []
        changed = False
        for key in sorted(set(fa) | set(fb)):
            if key in fa and key in fb:
                items.append({"id": (key[0] or key[1] or "-"), "classification": UNCHANGED})
            elif key in fa:
                changed = True
                items.append({"id": (key[0] or key[1] or "-"), "classification": REMOVED,
                              "reason": "finding absent from B (A and B correlation both completed)"})
            else:
                changed = True
                items.append({"id": (key[0] or key[1] or "-"), "classification": NEW})
        return {"aspect": "correlation", "classification": CHANGED if changed else UNCHANGED,
                "a": "%d finding(s)" % len(fa), "b": "%d finding(s)" % len(fb),
                "items": items}

    reasons = []
    for side, st, rec in (("A", a_st, ca), ("B", b_st, cb)):
        research = (evA if side == "A" else evB).get("vulnerabilities") or {}
        r_st = research.get("status") or "not-run"
        if r_st == "not-run":
            reasons.append("%s no research to correlate" % side)
        elif st == "completed":
            reasons.append("%s completed" % side)
        elif st in ("failed", "not-run"):
            reasons.append("%s correlation %s" % (side, st))
        else:
            reasons.append("%s correlation %s" % (side, st))
    return {"aspect": "correlation", "classification": UNKNOWN,
            "a": a_st, "b": b_st, "reason": "; ".join(reasons)}


def compare_exploitation(evA, evB):
    xa = evA.get("exploitation") or {}
    xb = evB.get("exploitation") or {}
    a_st = xa.get("status") or "not-run"
    b_st = xb.get("status") or "not-run"
    if a_st == b_st == "not-run":
        return None
    rel_a = a_st in RELIABLE_EXPLOIT
    rel_b = b_st in RELIABLE_EXPLOIT
    if rel_a and rel_b:
        changed = a_st != b_st or (xa.get("session_type") or None) != (xb.get("session_type") or None)
        return {"aspect": "exploitation", "classification": CHANGED if changed else UNCHANGED,
                "a": "%s (session %s)" % (a_st, xa.get("session_id") or "-"),
                "b": "%s (session %s)" % (b_st, xb.get("session_id") or "-")}
    reasons = []
    for side, st in (("A", a_st), ("B", b_st)):
        if st in RELIABLE_EXPLOIT:
            reasons.append("%s %s" % (side, st))
        elif st == "not-run":
            reasons.append("%s exploitation not performed" % side)
        elif st == "dependency-missing":
            reasons.append("%s dependency-missing" % side)
        else:
            reasons.append("%s %s" % (side, st))
    return {"aspect": "exploitation", "classification": UNKNOWN,
            "a": a_st, "b": b_st, "reason": "; ".join(reasons)}


def compare_evidence(evA, evB):
    ea = evA.get("evidence") or {}
    eb = evB.get("evidence") or {}
    a_st = ea.get("status") or "not-run"
    b_st = eb.get("status") or "not-run"
    if a_st == b_st == "not-run":
        return None
    rel_a = a_st in RELIABLE_EXPLOIT
    rel_b = b_st in RELIABLE_EXPLOIT
    if rel_a and rel_b:
        return {"aspect": "evidence", "classification":
                UNCHANGED if a_st == b_st else CHANGED,
                "a": a_st, "b": b_st}
    reasons = []
    for side, st in (("A", a_st), ("B", b_st)):
        reasons.append("%s evidence %s" % (side, st or "not-run"))
    return {"aspect": "evidence", "classification": UNKNOWN,
            "a": a_st, "b": b_st, "reason": "; ".join(reasons)}


# ------------------------------------------------------------------
# Target-level classification
# ------------------------------------------------------------------

def classify_pair(target, evA, evB):
    notes = []
    aspects = []

    disc = compare_discovery(evA, evB)
    aspects.append(disc)

    if disc.get("hosts_up") is False:
        # both hosts definitively down -> nothing else to compare
        return {"classification": UNCHANGED, "skip_detail": True, "notes": notes,
                "aspects": [disc]}
    if disc.get("classification") in (REMOVED, CHANGED):
        return {"classification": disc["classification"], "notes": notes +
                [disc.get("reason", "")], "aspects": [disc]}

    ports = compare_ports(evA, evB)
    aspects.append(ports)

    res = compare_research(evA, evB)
    if res:
        aspects.append(res)
    corr = compare_correlation(evA, evB)
    if corr:
        aspects.append(corr)
    ex = compare_exploitation(evA, evB)
    if ex:
        aspects.append(ex)
    evid = compare_evidence(evA, evB)
    if evid:
        aspects.append(evid)

    changed = any(a.get("classification") == CHANGED for a in aspects) or \
        any(p.get("classification") in (NEW, REMOVED, CHANGED)
            for p in (ports.get("comparisons") or []))
    nc = any(a.get("classification") == NOT_COMPARABLE for a in aspects) or \
        any(p.get("classification") == NOT_COMPARABLE
            for p in (ports.get("comparisons") or []))
    unknown = any(a.get("classification") == UNKNOWN for a in aspects) or \
        any(p.get("classification") == UNKNOWN
            for p in (ports.get("comparisons") or []))
    compared = any(a.get("classification") in (UNCHANGED, CHANGED)
                   for a in aspects) or bool(ports.get("comparisons"))

    if changed:
        cls = CHANGED
    elif nc:
        cls = NOT_COMPARABLE
    elif unknown:
        cls = UNKNOWN
    elif compared:
        cls = UNCHANGED
    else:
        cls = UNKNOWN
    return {"classification": cls, "skip_detail": False, "notes": notes,
            "aspects": aspects, "ports": ports}


def summarize_target(root, aid, target):
    return te.collect_target_evidence(root, aid, target)


# ------------------------------------------------------------------
# Output formatting
# ------------------------------------------------------------------

def _port_line(c, indent="    "):
    if c.get("protocol") and c.get("protocol") != "-":
        label = "%s/%s" % (c.get("port"), c.get("protocol"))
    else:
        label = c.get("port", "?")
    line = "%s%s  %-13s" % (indent, label, c.get("classification"))
    if c.get("service_a") and c.get("service_b"):
        if c.get("service_a") == c.get("service_b"):
            line += "  service: %s" % c["service_a"]
        else:
            line += "  A: %s | B: %s" % (c.get("service_a"), c.get("service_b"))
    elif c.get("service_a"):
        line += "  A: %s" % c["service_a"]
    elif c.get("service_b"):
        line += "  B: %s" % c["service_b"]
    if c.get("reason"):
        line += "  (%s)" % c["reason"]
    return line


def format_target(target, rec):
    lines = ["  Target: %s" % target,
             "    classification: %s" % rec["classification"]]
    if rec["kv"].get("scopes"):
        lines.append("    scopes: A=[%s] B=[%s]"
                     % (", ".join(rec["kv"]["a_scopes"]) or "-",
                        ", ".join(rec["kv"]["b_scopes"]) or "-"))
    for aspect in rec["kv"].get("aspects", []):
        a = aspect
        label = a.get("aspect", "?")
        if a.get("classification") == UNKNOWN:
            lines.append("    %-12s %-12s  %s"
                         % (label, a["classification"], a.get("reason") or ""))
        else:
            detail = ""
            if label == "discovery":
                detail = "A=%s B=%s" % (a.get("a"), a.get("b"))
            elif label == "ports":
                detail = ""
            elif "a" in a and "b" in a:
                detail = "A: %s | B: %s" % (a.get("a"), a.get("b"))
            lines.append("    %-12s %-12s  %s"
                         % (label, a.get("classification", "?"), detail))
    ports = rec["kv"].get("ports")
    if ports and ports.get("comparisons"):
        lines.append("    ports:")
        for c in ports["comparisons"]:
            lines.append(_port_line(c, "      "))
    for aspect in rec["kv"].get("aspects", []):
        for item in aspect.get("items") or []:
            lines.append("        %-12s %s"
                         % (item.get("classification"),
                            item.get("id") + ("  (%s)" % item.get("reason") if item.get("reason") else "")))
    for n in rec.get("notes", []):
        if n:
            lines.append("    note: %s" % n)
    a_ev = rec.get("evidence_a") or {}
    b_ev = rec.get("evidence_b") or {}
    root_a = os.path.join(rec.get("root_a", ""), "").rstrip("/")
    root_b = os.path.join(rec.get("root_b", ""), "").rstrip("/")
    art = []
    for side, ev in (("A", a_ev), ("B", b_ev)):
        refs = []
        for name in ("discovery", "enumeration", "vulnerabilities", "correlation",
                     "exploitation", "evidence"):
            p = (ev.get(name) or {}).get("artifact") or (ev.get(name) or {}).get("dir")
            if p:
                refs.append("%s:%s" % (name, p))
        if refs:
            art.append("%s artifacts: %s" % (side, " ".join(refs)))
    for line in art:
        lines.append("    " + line)
    return lines


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def run(root, aid_a, aid_b, outdir):
    try:
        ma, ka = te.load_manifest(root, aid_a)
        mb, kb = te.load_manifest(root, aid_b)
    except te.EvidenceError as exc:
        print("[-] %s" % exc, file=sys.stderr)
        return 1

    adir_a = te.assessment_dir(root, aid_a)
    adir_b = te.assessment_dir(root, aid_b)
    targets_a = te.list_targets(ma, adir_a, ka)
    targets_b = te.list_targets(mb, adir_b, kb)

    if not targets_a and not targets_b:
        print("[-] Comparison not possible: neither assessment has a target identity "
              "(refusing to fabricate a comparison).", file=sys.stderr)
        return 1

    all_targets = sorted(set(targets_a) | set(targets_b))
    results = []
    for t in all_targets:
        key = te.safe_name(t)
        evA = te.collect_target_evidence(root, aid_a, t) if t in targets_a else None
        evB = te.collect_target_evidence(root, aid_b, t) if t in targets_b else None
        rec = {"target": t, "key": key, "root_a": adir_a, "root_b": adir_b,
               "notes": [], "kv": {}}
        if evA is None and evB is None:
            continue
        if evA is None:
            if reliable_present(evB):
                rec["classification"] = NEW
                rec["notes"].append("present in B with reliable evidence; absent from A")
            else:
                rec["classification"] = UNKNOWN
                rec["notes"].append("in B but no reliable observation (cannot confirm NEW)")
            rec["kv"] = {"scopes": False, "a_scopes": [], "b_scopes": evB.get("scopes", []),
                         "aspects": [], "ports": None}
            rec["evidence_a"] = None
            rec["evidence_b"] = summarize_refs(evB)
        elif evB is None:
            rec["classification"] = UNKNOWN
            rec["notes"].append("present in A only; not in later assessment - absence from a "
                                "later scope is not evidence of removal")
            rec["kv"] = {"scopes": False, "a_scopes": evA.get("scopes", []),
                         "b_scopes": [], "aspects": [], "ports": None}
            rec["evidence_a"] = summarize_refs(evA)
            rec["evidence_b"] = None
        else:
            pair = classify_pair(t, evA, evB)
            rec["classification"] = pair["classification"]
            rec["notes"].extend(pair["notes"])
            rec["kv"] = {"scopes": True, "a_scopes": evA.get("scopes", []),
                         "b_scopes": evB.get("scopes", []),
                         "aspects": pair.get("aspects", []),
                         "ports": pair.get("ports")}
            rec["evidence_a"] = summarize_refs(evA)
            rec["evidence_b"] = summarize_refs(evB)
        results.append(rec)

    results.sort(key=lambda r: (CLASSES.index(r["classification"]), r["target"]))

    summary = {c: sum(1 for r in results if r["classification"] == c)
               for c in CLASSES}

    lines = []
    lines.append("Assessment Comparison")
    lines.append("=====================")
    lines.append("")
    lines.append("A: %s (%s, %d target(s))" % (aid_a, "scope-based" if ka == "scope" else "single-target", len(targets_a)))
    lines.append("B: %s (%s, %d target(s))" % (aid_b, "scope-based" if kb == "scope" else "single-target", len(targets_b)))
    lines.append("")
    lines.append("Targets")
    lines.append("-------")
    for cls in CLASSES:
        lines.append(cls)
        picks = [r for r in results if r["classification"] == cls]
        if picks:
            for r in picks:
                lines.append("  %s" % r["target"])
        else:
            lines.append("  none")

    for r in results:
        if r["classification"] in (UNCHANGED,):
            continue  # compact: unchanged targets summarized below
        lines.append("")
        lines.extend(format_target(r["target"], r))

    lines.append("")
    lines.append("UNCHANGED targets")
    lines.append("-----------------")
    unchanged = [r for r in results if r["classification"] == UNCHANGED]
    if unchanged:
        for r in unchanged:
            lines.append("  %s" % r["target"])
    else:
        lines.append("  none")

    lines.append("")
    lines.append("Summary: "
                 + ", ".join("%s=%d" % (c, summary[c]) for c in CLASSES))

    stdout_text = "\n".join(lines)
    print(stdout_text)

    # ---- artifact
    if not os.path.isdir(outdir):
        os.makedirs(outdir, exist_ok=True)

    json_targets = []
    comparisons_flat = []
    for r in results:
        jt = {
            "target": r["target"],
            "key": r["key"],
            "classification": r["classification"],
            "notes": r["notes"],
            "scopes_a": r["kv"].get("a_scopes", []) if r["kv"].get("scopes") else None,
            "scopes_b": r["kv"].get("b_scopes", []) if r["kv"].get("scopes") else None,
            "evidence_a": r.get("evidence_a"),
            "evidence_b": r.get("evidence_b"),
        }
        ports = r["kv"].get("ports")
        if ports:
            jt["ports"] = {
                "reliable_a": ports.get("reliable_a"),
                "reliable_b": ports.get("reliable_b"),
                "comparisons": ports.get("comparisons", []),
            }
        aspects = r["kv"].get("aspects") or []
        jt["aspects"] = aspects
        for a in aspects:
            comparisons_flat.append({
                "target": r["target"], "aspect": a.get("aspect"),
                "classification": a.get("classification"),
                "reason": a.get("reason", ""),
            })
        jt["research_a"] = None
        jt["research_b"] = None
        json_targets.append(jt)

    payload = {
        "tool": "security-assessment",
        "phase": 12,
        "phase_label": "history-comparison",
        "assessment_a": aid_a,
        "assessment_b": aid_b,
        "kind_a": ka,
        "kind_b": kb,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z"),
        "a_targets": targets_a,
        "b_targets": targets_b,
        "summary": summary,
        "targets": json_targets,
        "comparisons": comparisons_flat,
    }
    with open(os.path.join(outdir, "comparison.json"), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")

    with open(os.path.join(outdir, "summary.txt"), "w", encoding="utf-8") as fh:
        fh.write(stdout_text + "\n")

    with open(os.path.join(outdir, "status.txt"), "w", encoding="utf-8") as fh:
        fh.write("status=completed\n")
        fh.write("assessment_a=%s\n" % aid_a)
        fh.write("assessment_b=%s\n" % aid_b)
        fh.write("comparison_dir=%s\n" % outdir)
        for cls in CLASSES:
            fh.write("%s=%d\n" % (cls.lower(), summary[cls]))

    return 0


def summarize_refs(ev):
    """Small reference view (artifact paths + per-aspect status), not a copy
    of every finding - findings stay where they are historically."""
    out = {"target": ev.get("target"), "kind": ev.get("kind"),
           "state": ev.get("state")}
    for name in ("discovery", "enumeration", "vulnerabilities", "correlation",
                 "exploitation", "evidence", "report"):
        rec = ev.get(name) or {}
        entry = {"status": rec.get("status")}
        p = rec.get("artifact") or rec.get("dir")
        if p:
            entry["artifact"] = p
        if name == "enumeration":
            entry["open_ports"] = rec.get("open_ports", 0)
            entry["no_open_ports"] = rec.get("no_open_ports", False)
        if name == "vulnerabilities":
            entry["candidates"] = len(rec.get("candidates") or [])
            entry["services"] = len(rec.get("services") or [])
        if name == "correlation":
            entry["findings"] = len(rec.get("findings") or [])
        if name == "exploitation":
            entry["session_id"] = rec.get("session_id")
            entry["session_type"] = rec.get("session_type")
            entry["selected_module"] = rec.get("selected_module")
        if name == "evidence":
            entry["session_id"] = rec.get("session_id")
        if rec.get("reason"):
            entry["reason"] = rec["reason"]
        out[name] = entry
    return out


def main_cli():
    if len(sys.argv) != 5:
        print("Usage: %s <assessments_root> <assessment_A> <assessment_B> <out_dir>"
              % os.path.basename(sys.argv[0]), file=sys.stderr)
        return 1
    root, a, b, outdir = sys.argv[1:5]
    try:
        return run(root, a, b, outdir)
    except OSError as exc:
        print("[-] Could not read historical data: %s" % exc, file=sys.stderr)
        return 1
    except te.EvidenceError as exc:
        print("[-] %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main_cli())