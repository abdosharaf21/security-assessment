# Implementation Report

Security-assessment platform (Bash + Metasploitable-2 lab). Final implementation
report for the requested hardening scope: Bug #1 (Quick Scan -> Vulnerability
Research integration), Bug #2 (Metasploit runner compatibility), Quick Scan
phase-control UX, Scope CLI verification, Assessment reuse/immutability
verification, and full-regression coverage.

All numbers below are from real, reproducible runs of `./tests/test_tool.sh`
on this host (offline; the two environment-dependent tests are identified in
Section 11).

---

## 1. Scope and method

Changes were confined to the platform's own scripts and its hermetic test
suite. The pre-existing, uncommitted work in the working tree (correlation
wildcard `vtuple` fix, exploitation/README/report/scanner/test improvements)
was preserved throughout. Test targets are reserved-documentation ranges
(203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24, 192.168.1.0/24) and every
external binary is a `tests/fakes/` shim, so the suite is deterministic and
safe to run without a live lab.

Regression harness: `tests/test_tool.sh` (baseline **PASS 344 / FAIL 4**,
where the 4 failing assertions are the two environment-dependent tests t05/t06).

---

## 2. Bug #1 — Quick Scan → legacy Vulnerability Research fails

### Symptom
`./scanner.sh scan <target> --quick` runs Discovery + Enumeration and writes the
Stage-2 enumeration XML under `output/assessments/<id>/enumeration/`. A
subsequent legacy `./scanner.sh <target> vulnerabilities` could not see that XML
and exited `EXIT_NO_XML` (rc=2): *"No usable enumeration XML found for target"*.
The Quick Scan therefore produced data that the standalone Vulnerability phase
silently ignored.

### Root cause
`modules/vulnerability.sh` only searched the legacy `output/enumeration/`
directory via `sat_enum_service_xml`; assessment-scoped artifacts were out of its
resolution path.

### Fix
1. New resolver `sat_assessment_enum_xml <target>` in `lib/common.sh:281`
   (self-contained; parses each `$ASSESSMENTS_ROOT/assessment_*/manifest.json`,
   matches on `target`, prefers the **newest** assessment, delegates to
   `sat_enum_service_xml`, and never returns Stage-1 `*.ports.xml`).
2. `modules/vulnerability.sh:346-358` — resolution order is now:
   explicit XML argument (always wins) → assessment-scoped artifact → legacy
   standalone enumeration. Stage-1 artifacts and no-artifact cases behave as
   before (honest rc=2).

### Tests
`_write_assessment_enum` helper + `t68_enum_xml_resolution`: legacy-only,
assessment-over-legacy, newest-assessment selection, Stage-1 exclusion, explicit
path wins, Stage-1-only rc=2, no-artifact rc=2, malformed assessment XML rc=1,
and an end-to-end `scan --quick` → legacy `vulnerabilities` reuse. **18 assertions,
all passing.** Full suite after this section: PASS 362 / FAIL 4.

---

## 3. Bug #2 — Metasploit runner compatibility

### Symptom
The Phase-5 exploitation runner failed against real (release) `msfconsole`:

```
set PAYLOAD cmd/unix/interact
[-] The value specified for PAYLOAD is not valid.
[*] Using configured payload cmd/linux/http/x86/meterpreter_reverse_tcp

set ExitOnSession false
[!] Unknown datastore option: ExitOnSession.

show options (module default payload):
   LHOST ... yes ...          <- required, but never set
[-] Exploit failed: OptionValidateError ... LHOST

sessions -C "...evidence..."  (no -i)
Please specify valid session identifier(s) using -i
```

The configured `cmd/unix/*` payloads are rejected, msf falls back to a module
default reverse payload that **requires** LHOST, `ExitOnSession` is unknown in
this build, and `sessions -C` needs a real session id supplied with `-i`. The
harness never validated the payload, never resolved LHOST, never nested
evidence behind a detected session, and did not distinguish a timeout from a
genuine failure.

### Fix (three-stage, bounded runner — `modules/exploitation.sh`)
- **Probe** (`probe_compat` at `exploitation.sh:114`, resource via
  `make_probe_resource:79`): one msfconsole run (`use <module>; set PAYLOAD
  <p>; set ExitOnSession false; show options; exit -y`) that parses the build's
  own answers:
  - `The value specified for PAYLOAD is not valid.` → payload invalid;
    `set PAYLOAD` is **omitted** from the launch script and the module default
    payload is used and recorded (`payload_used=module-default`).
  - `Unknown datastore option: ExitOnSession.` → the `set ExitOnSession false`
    line is omitted (never sent).
  - `show options` row `LHOST ... yes` → LHOST is required.
- **LHOST resolution** before any approval/launch:
  `--lhost` arg > `MFE_LHOST` env/config > `LHOST` env. The value is validated,
  **never** defaults to the target address, and a required-but-unset LHOST
  aborts with a clear, exploitable message (rc=1, no artifacts, no msf launch).
  New optional key `MFE_LHOST` is documented in `config/config.conf`.
- **Launch**: only supported options are emitted; `exploit -j -z; sleep 5;
  sessions -l; exit -y`.
- **Evidence** (`make_evidence_resource:91`): message and commands are issued
  **only** after a real session id has been detected from launch output, using
  the correct form `sessions -c '<cmd>' -i <id>`; the evidence resource is
  saved as `<dir>/msf_evidence.res` and its output appended to
  `exploit_output.txt` so `modules/evidence.sh` markers keep working. A session
  id is never fabricated.
- **Timeout honesty**: every msfconsole run is bounded and `run_msf`
  (`exploitation.sh:102`) runs with stdin from `/dev/null` so the approval
  prompt pipe is never consumed. A `timeout` kill (rc 124) is recorded in
  `result.txt` as `msfconsole_timeout=yes` and in `status.txt`; it is
  **never** success.
- **Honest result record**: `result.txt` now carries `payload_valid`,
  `payload_used`, `default_payload`, `exit_onsession_supported`,
  `lhost_required`, `lhost`, `msfconsole_exit`, `msfconsole_timeout`,
  `probe_exit`, and the existing `session_status`/`session_type`/`session_id`.
- **`--dry-run`**: prints the would-run plan (payload/LHOST/ExitOnSession
  finalized at run time), exits 0, executes nothing, writes no artifacts.
- `tests/fakes/msfconsole` now simulates the release build's probe/launch/
  evidence behavior, with knobs `FAKE_MSF_LHOST_REQUIRED`, `FAKE_MSF_HANG`,
  `FAKE_MSF_FAIL`, `FAKE_MSF_NO_OPEN`.

### Tests
New `t69_exploit_invalid_payload_fallback`, `t70_exploit_lhost_required_missing`,
`t71_exploit_lhost_provided` (incl. `--lhost` precedence over `MFE_LHOST`),
`t72_exploit_lhost_never_target`, `t73_exploit_timeout_not_success`,
`t74_exploit_no_session_no_evidence`, `t75_exploit_dry_run`,
`t76_exploit_launch_failure_honest` — **35 assertions, all passing**.
Full suite after this section: PASS 397 / FAIL 4.

---

## 4. Evidence-phase compatibility

`modules/evidence.sh` is untouched. Its markers (`SAT_HOSTNAME_START` …
`SAT_EVIDENCE_END`) are still read from `<dir>/exploit_output.txt`, and the new
runner appends the evidence-stage output (with a separator header) to that same
file, so `t15_evidence_session` / `t16_evidence_no_session` still pass
unchanged while proving the markers are only produced through a real detected
session.

---

## 5. Quick Scan phase-control UX

### Requirement (confirmed)
Quick Scan intentionally performs Discovery + Enumeration only, and the existing
`resume <assessment-id>` mechanism already continues the pipeline. No new
`--no-next`/`--stop-after` flag was added. The only addition is a minimal,
non-automatic next-step hint compatible with the existing `[?] ...` interactive
style.

### Change (`scanner.sh:456-478`)
After a successful quick scan:
- Always prints `[+] Quick scan complete: <id>` and
  `Continue later with: ./scanner.sh resume <id>`.
- Only when **stdin and stdout are both interactive TTYs** (`[[ -t 0 && -t 1 ]]`)
  offers `Start Vulnerability Research now? [y/N]`. The default is **N** —
  nothing is ever executed automatically. Piped/CI invocation is unchanged
  apart from the informational hint line.

### Tests
`t78_quick_scan_next_step`: quick scan succeeds, hint names `resume`, the
interactive prompt never appears in non-interactive runs, and no
vulnerability-research artifacts are produced. Combined with the existing
`t37_scan_quick_resume` (quick → resume completes vulnerabilities/correlation/
report with no reruns).

---

## 6. Scope CLI — verified, no bug

### Finding
The current parser is intentional: `scope create <assessment-id> <targets...>
[--name <n>] [--parent <scope_id>]` — every positional argument after the
assessment id is a target; the earlier live-test confusion came from the
incorrect invocation `scope create <aid> lab-scope 192.168.1.84`, which is
correctly interpreted as two targets. **The parser was left unchanged.

### Regression tests (new)
`t79_scope_create_name` — documented single-host form with `--name lab-scope`:
`name=lab-scope`, `type=ip`, `target_count=1`, target preserved, status
`pending`; a second create yields a second scope id and never overwrites the
first.
`t80_scope_create_cidr` — `192.168.1.0/24 --name lab-scope`: `type=cidr`,
expanded to 254 hosts, `.0`/`.255` excluded.
`t81_scope_create_dedupe_hostname` — duplicate IP deduplicated, hostname
lowercased, target_count correct, `type=hostname`.
`t82_scope_list_show_status` — `scope list <aid>`, `scope show <sid>`,
`scope status <sid>` all reflect the persisted metadata.
**29 assertions, all passing.** (Target normalization, dedupe, IP/CIDR/
hostname classification, `--name` preservation and metadata persistence are all
verified; no assessment or historical artifact is overwritten — see Section 7.)

---

## 7. Assessment reuse / immutability — verified

`sat_assessment_create` always allocates a fresh `assessment_*` id;
`sat_assessment_ensure` is idempotent and only creates a missing shell (it
prints `[+] Assessment created:` only when it actually creates; on an existing
assessment it returns early without touching anything).

`t83_assessment_reuse_immutability` proves:
- two `scan <target> --quick` runs yield two **distinct** assessments (2 total),
- the first assessment is byte-identical (file list + `manifest.json`) after the
  second scan,
- resuming one assessment completes its remaining phases while leaving the other
  assessment completely untouched,
- `scope create` on an existing assessment leaves `manifest.json` byte-identical
  and prints no recreate message.

**7 assertions, all passing.**

---

## 8. Exit-code propagation and report status

Verified via `set -euo pipefail` and explicit pipeline handling:
- Legacy single-phase failures propagate the module exit code to the CLI
  (e.g. `scanner.sh <target> vulnerabilities` with no enumeration data → rc=2).
- Assessment `resume` stops the chain on a failing phase, records the phase in
  `failed_phases` (never `completed_phases`), still produces an honest report,
  sets the manifest `status=failed`, and exits nonzero.
- `report status: completed` means "report generation completed", including the
  honest-failure path (unchanged semantics).

`t84_pipeline_error_propagation` locks these in (5 assertions; includes the
poisoned-assessment-XML resume path and the legacy single-phase rc=2 path).

---

## 9. Retained earlier fixes (regression-guarded)

- Correlation wildcard semantics (`vtuple`, `t67_corr_wildcard_versions`) —
  untouched and still passing.
- Legacy exploit-phase argument forwarding (`phase_exploit "${@:3}"`,
  `t66_scanner_exploit_forward`) — untouched and still passing.
- Enumeration V2 multi-stage / artifact rules (t41–t60), searchsploit failure
  honesty (t60), vulnerability autoselect (t55), report stage-2 text (t56).

---

## 10. Safety and configuration

Safety posture is unchanged and reinforced:
- `AUTO_EXPLOIT=false`, `REQUIRE_EXPLOIT_APPROVAL=true` (config + fixture).
- Exploitation runs only with explicit in-run approval; the approval prompt is
  never reached for an unmapped candidate (t63).
- Every msfconsole invocation runs within `MFE_TIMEOUT` (default 120s) and
  treats a timeout as honest failure — never success.
- Symbol/metacharacter filtering for scope targets, bounded CIDR expansion
  (default `SCOPE_MAX_EXPANDED_TARGETS=256`), and no target used as a listener
  (`LHOST` never defaults to the target).
- New optional config key `MFE_LHOST` (attacker-side listener for reverse
  payloads; empty by default → clear failure, not a guess).
- `exploitation.sh` gained `--dry-run` and `--lhost` (documented in `usage()`).

---

## 11. Full-suite results

Final run of `./tests/test_tool.sh` (offline):

```
 RESULTS: PASS=444 FAIL=4 SKIP=0
 Failed tests:
   0) t05 vuln without searchsploit rc=3
   1) t05 status dependency-missing
   2) t06 exploit without msfconsole rc=3
   3) t06 status dependency-missing
```

The only failures are the two **environment-dependent** baseline tests: this
host has real `/usr/bin/searchsploit` and `/usr/bin/msfconsole`, so the
dependency-missing paths (rc=3) cannot be reproduced here. They were present in
the untouched baseline (PASS 344 / FAIL 4) and were deliberately not weakened
or skipped.

| Milestone | PASS | new assertions |
|-----------|------|----------------|
| Baseline (pre-change) | 344 | – |
| Bug #1 + t68 | 362 | +18 |
| Bug #2 + t69–t76 | 397 | +35 |
| Quick Scan(78)/Scope(79–82)/Assessment(83)/Exit-code(84) | 444 | +47 |

New tests added: `t68`, `t69`–`t76`, `t78`, `t79`–`t82`, `t83`, `t84`
(16 functions, 100 fresh assertions).

Progression on this host across the whole task (before this work the tree ran
344 PASS / 4 FAIL, with no suite runs on record for the changed modules):
**344 → 362 → 397 → 444 PASS**, with the identical 4 environment-dependent
failures throughout.

---

## 12. Backward compatibility

- Legacy CLI is unchanged: `./scanner.sh <target> <phase>` and
  `./scanner.sh <target> full|all` behave as before, with phase exit codes
  propagated during this work.
- `scan`/`status`/`resume`/`scope`/`history`/`compare`/`preflight`/`menu`
  behavior unchanged except the additive quick-scan hint.
- All new configuration is optional and additive (`MFE_LHOST`); environment
  variables still override `config.conf`.
- Assessment artifacts, scope metadata layout, result/status/JSON record shapes
  for existing phases are unchanged; only exploitation phase records gained new
  honest fields.
- Existing tests t01–t67 pass exactly as at baseline (after accounting for the
  fixed Bug #1 path); no pre-existing behavior relied on an invalid
  `set PAYLOAD`, untyped `sessions -C`, or LHOST-invalid runs, so the Bug #2
  runner change is expected to only remove failure modes.