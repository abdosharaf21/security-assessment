# Security Assessment Tool (Bash)

A modular, evidence-first security assessment pipeline built in Bash for the
**authorized Metasploitable 2 lab target only**. Every phase writes real
artifacts under `output/`; nothing is fabricated — if a phase could not run,
found nothing, or produced a partial result, the tool says so in a status file.

Version **1.0.0**. This document describes the shipped implementation (`v1.0.0`
tag == `632e025`), not aspirational features.

## Contents

1. [Scope and safety](#scope-and-safety)
2. [Requirements](#requirements)
3. [Architecture](#architecture)
4. [Assessment model](#assessment-model)
5. [CLI reference](#cli-reference)
6. [Quick Scan vs Full Scan](#quick-scan-vs-full-scan)
7. [Enumeration V2](#enumeration-v2)
8. [Artifact selection semantics](#artifact-selection-semantics)
9. [SearchSploit compatibility](#searchsploit-compatibility)
10. [Safety model](#safety-model)
11. [Exit codes](#exit-codes)
12. [Correlation rules](#correlation-rules)
13. [Evidence / session handling](#evidence--session-handling)
14. [Configuration](#configuration)
15. [Testing](#testing)
16. [Project structure](#project-structure)
17. [Known limitations](#known-limitations)
18. [Roadmap / V2](#roadmap--v2)
19. [Examples](#examples)

## Scope and safety

- Designed for the **Metasploitable 2** lab target on an isolated network; the
  banner and report title state this explicitly.
- The target is **user-supplied** and validated (`sat_validate_target`): no
  option injection, no shell metacharacters, no whitespace. No target is
  hardcoded.
- Exploitation is **approval-gated** and never executed automatically.
- Findings and statuses come from real outputs only. No CVE/CVSS data is
  manufactured; confidence and severity are the tool's own deterministic,
  documented rules.

## Requirements

- `bash` 4+
- `nmap` — Phases 1–2 (and 5)
- `python3` — XML/JSON parsing, correlation, history/compare evidence, reports
- `searchsploit` (exploitdb) — Phase 3, **optional** (see
  [SearchSploit compatibility](#searchsploit-compatibility))
- `msfconsole` (Metasploit) — Phase 5, lab-only, **optional**

Phase dependencies are checked per run and a missing one is recorded as
`status=dependency-missing` with exit code `3` — it is never reported as a
success. `./scanner.sh preflight` reports every required/optional tool up front.
`./scanner.sh scan --dry-run` prints the exact dependency expectations with
zero side effects.

## Architecture

```
scanner.sh                    controller (unified CLI + legacy dispatch)
lib/common.sh                 shared helpers: config, exit codes, target
                              validation, artifact selection
lib/assessment.sh             assessment manager: IDs, manifest, resume plans
lib/scope.sh                  scope management (multi-target assessments)
lib/scope_worker.sh           bounded per-target worker (run inside `timeout`)
lib/history.py                read-only audit log of assessments/scopes
lib/comparison.py             read-only evidence-aware assessment comparison
lib/target_evidence.py        read-only evidence model shared by history/compare
  modules/discovery.sh        Phase 1  host discovery (nmap ping scan)
  modules/enumeration.sh      Phase 2  Enumeration V2 (3-stage, see below)
    modules/service_handlers/ Phase 2  read-only service handlers
    modules/vulnerability.sh  Phase 3  Nmap services -> SearchSploit research
    modules/correlation.sh    Phase 4  deterministic confidence + severity
    modules/exploitation.sh   Phase 5  candidate selection, approval, session detect
    modules/evidence.sh       Phase 6  honest session/evidence record
    modules/report.sh         Phase 7  Markdown + HTML report
config/                       config.conf, exploit_mapping.conf
output/                       legacy per-phase artifacts, plus:
output/assessments/           isolated per-assessment runs (manifest.json + phases)
output/comparisons/           read-only compare output
reports/                      generated legacy reports
tests/                        harness, fixtures, fake external tools
```

The phase pipeline is: **discovery → enumeration → vulnerabilities →
correlation → (exploitation, approval-gated) → evidence → report**.

## Assessment model

Every `scan` creates a **new, isolated assessment** that never touches another
assessment's artifacts.

```
Assessment
    ↓
Assessment ID  (assessment_<yyyymmdd_hhmmss_nanoseconds>)
    ↓
isolated artifacts/state   (output/assessments/<id>/<phase>/<target>_<ts>.*)
    ↓
phase execution            (per-phase status recorded in manifest.json)
```

- **Assessment IDs** are nanosecond-timestamped and collision-free
  (`sat_assessment_id_new`); historical artifacts of one assessment are never
  overwritten by later runs.
- **Layout** — `output/assessments/<id>/` contains `manifest.json` plus the
  `discovery/`, `enumeration/`, `vulnerabilities/`, `correlation/`,
  `exploitation/`, `evidence/`, `report/` phase dirs. Scope-based assessments
  add `scopes/<scope_id>/` with `scope.json`, a per-target `registry/`, and
  per-target isolated `targets/<key>/<phase>/` artifacts.
- **Manifest** (`manifest.json`) — plain metadata, never secrets:
  `assessment_id`, `target`, `started_at`, `updated_at`, `status`, `current_phase`,
  `completed_phases[]`, `failed_phases[]`. It is only ever updated from real
  phase outcomes; a missing/corrupt manifest is refused rather than guessed at.
- **`scope create`** (auto-)creates the assessment if the id does not yet exist,
  then normalizes/deduplicates targets and expands CIDR ranges up to
  `SCOPE_MAX_EXPANDED_TARGETS=256` (anything larger is refused).

Multi-target scoped assessments layer as:

```
Assessment
    └── Scope (scope_<ts>)
          └── Targets (normalized, deduped, CIDR-expanded)
                └── per-target state + isolated artifacts
```

### Commands behind the model

- **`status [<id>]`** — list all assessments or show one assessment's phase
  table. Phase state is derived from the manifest *and* real artifacts: e.g. a
  phase marked completed whose artifacts are missing is flagged
  `completed (artifacts missing!)`. Exploitation not run is shown
  `manual-only (not run)`; evidence without an exploitation result is
  `skipped (no exploitation result)`. Scoped assessments show their scopes.
- **`resume <id> [--dry-run]`** — rebuilds the plan from the manifest: completed
  phases are skipped, failed phases are retried, and **exploitation is never
  included** (evidence only if a real exploitation result exists). With
  `--dry-run` the plan is only printed. For scoped assessments, resume works
  per scope over pending/failed targets.
- **`preflight [<target>]`** — required/optional tools, config file presence,
  scope/parallel settings, output writability, and an informational ICMP check
  (the authoritative reachability check still happens in Phases 1–2 at scan
  time).
- **`report <id>`** — (re)generates a report from an existing assessment.
- **`--dry-run`** — creates no assessment and executes no command; it only
  prints what *would* happen (phases, module commands, artifact locations,
  per-phase dependencies). Zero side effects by design.

## CLI reference

The unified CLI (`./scanner.sh <command> ...`, see `--help`) plus the legacy
single-phase controller. Every command below was verified against the
implementation.

### Assessment commands

| Command | Meaning |
|---|---|
| `./scanner.sh scan <target> [--quick\|--full\|--dry-run]` | New isolated assessment. Default mode is `--full`. `--quick` = discovery + enumeration only; `--full` = discovery → enumeration → vulnerabilities → correlation → **exploitation (approval-gated)** → evidence → report; `--dry-run` prints the plan only. |
| `./scanner.sh status [<assessment-id>]` | List assessments, or the detailed phase state of one. |
| `./scanner.sh resume <assessment-id> [--dry-run]` | Skip completed, retry failed, **never exploit**. `--dry-run` prints the plan. |
| `./scanner.sh report <assessment-id>` | (Re)generate a report for an assessment. |
| `./scanner.sh preflight [<target>]` | Tool/config/writability/reachability checks. |
| `./scanner.sh menu` | Interactive menu (preflight, quick/full scan of a target, every phase, status, scope manager, history, compare). No auto-exploitation. `Ctrl+C` to exit. |
| `./scanner.sh --help` | Full usage text. |

The **legacy** `./scanner.sh <target> report` also exists: it re-generates a
report from the legacy per-phase artifacts under `output/` (using the same
Semantic Stage-2 artifact selection) and writes `reports/<target>_<ts>.md` /
`.html`.

### Scope commands

| Command | Meaning |
|---|---|
| `./scanner.sh scan <scope_id> [--new\|--failed\|--all\|--targets a,b,c] [--workers N] [--dry-run]` | Scan a scope's selected targets in a bounded worker pool (`--workers`, default `ENUMERATION_WORKERS=2`), one isolated output dir per target, each target bounded by `SCOPE_TARGET_TIMEOUT`. **Exploitation is never part of a worker.** Returns `0` (all ok), `2` (≥ 1 target failed), or `124` (≥ 1 worker timed out and was marked failed). |
| `./scanner.sh scope list [<assessment-id>]` | List scopes. |
| `./scanner.sh scope create <assessment-id> <targets...> [--name <n>] [--parent <scope_id>]` | Create a scope inside an assessment (auto-creates the assessment if needed); normalizes/dedupes targets, expands CIDRs with the size cap. |
| `./scanner.sh scope show <scope_id>` | Metadata + per-target summary of one scope. |
| `./scanner.sh scope status <scope_id>` | State/summary of one scope. |
| `./scanner.sh scope expand <scope_id> <targets...>` | Add targets to a scope. **Never deletes previous results.** Whether completed targets are rescanned is an explicit decision (`--new`/`--failed`/`--all`/`--targets`). |
| `./scanner.sh resume <assessment-id>` | For scoped assessments, resumes per scope instead of per phase. |

### History / compare

| Command | Meaning |
|---|---|
| `./scanner.sh history [<assessment-id>]` | Audit log of every assessment (summary), or a detailed read-only per-target view of one assessment. Pure read; never rewrites history. |
| `./scanner.sh compare <assessment-id-A> <assessment-id-B>` | Evidence-aware, read-only comparison. Output goes to a new dir under `output/comparisons/`, never into the assessments. Classifications: `NEW`, `REMOVED`, `CHANGED`, `UNCHANGED`, `UNKNOWN`, `NOT_COMPARABLE`. Failed/dependency-missing is never treated as absence. |

### Legacy phase commands (each runs ONLY its single phase)

```
./scanner.sh <target> discovery
./scanner.sh <target> enumeration
./scanner.sh <target> vulnerabilities
./scanner.sh <target> correlation
./scanner.sh <target> exploit            # exploitation ONLY (approval-gated)
./scanner.sh <target> evidence
./scanner.sh <target> report
./scanner.sh <target> full               # discovery -> enumeration -> vulnerabilities ->
                                         # correlation -> exploitation [approval REQUIRED] ->
                                         # evidence -> report
./scanner.sh <target> all                # discovery + enumeration only
```

Notes:

- Single-phase commands run **only that phase**; nothing is chained. After an
  `exploit` run, evidence and report must be invoked explicitly.
- There is **no** legacy `<target> quick` command; quick scanning is
  `./scanner.sh scan <target> --quick`.
- Each module can also be run standalone, e.g.
  `./modules/enumeration.sh 192.168.56.101` or
  `sudo ./modules/enumeration.sh 192.168.56.101` (sudo enables `-O`).

## Quick Scan vs Full Scan

- **Quick Scan** — `scan <target> --quick`. Intended for **discovery +
  enumeration only**. No vulnerability research, no correlation, no report, and
  no exploitation. It never touches exploitation.
- **Full Scan** — `scan <target> --full` (the default when no mode flag is
  given) and the legacy `<target> full`. This runs the broader assessment
  pipeline, ending in evidence + report. The exploitation phase is part of the
  plan **only** in the sense that it may be offered and **always requires an
  explicit interactive approval** before any candidate runs; if it is denied it
  is recorded honestly and evidence/report still capture the outcome.
- **Scope scans** never include exploitation at all.
- `--dry-run` and `resume` never include exploitation.

## Enumeration V2

Phase 2 is a three-stage evidence-first pipeline:

```
Stage 1   Fast port discovery (bounded, configurable port selection)
   ↓
Stage 2   Targeted service/version detection on discovered ports only
   ↓
Stage 3   Service-specific enumeration (read-only modular handlers)
```

### Stage 1 — port discovery

- Runs `nmap -T4 -Pn -n -sT --max-retries 1 ...`, wrapped in a bounded
  `timeout` (`ENUM_DISCOVERY_TIMEOUT`, default 300 s). A timeout is recorded,
  never reported as success.
- Port selection follows `ENUM_PORT_MODE`:
  - `top` (default) — top-N most common TCP ports (`ENUM_TOP_PORTS=100`);
  - `all` — full `-p-` scan of all 65 535 TCP ports;
  - `custom` — `NMAP_PORTS` (`-p <list/range>`). An explicitly exported
    `NMAP_PORTS` is always honored as `custom` for backward compatibility.
- Writes the Stage-1 artifact family: `*.ports.nmap.txt`, `*.ports.txt`,
  `*.ports.tsv`, `*.ports.xml`.
- **Unreachable** (no TCP response on any scanned port): reported with
  `status=unreachable`, the expensive service scan is never started, exit `2`.
- **Reachable with zero open ports**: a valid, evidence-based result recorded
  as `status=completed-no-open-ports`, exit `3`, never retried.

### Stage 2 — targeted service/version detection

- Runs `-sV` + NSE scripts only against the **discovered ports**
  (`-p <discovered_ports> -Pn -n`), with `-O` added when run as root.
- Safe default NSE category: `NMAP_SCRIPTS=default` (a `-sC` equivalent).
  Vulnerability NSE (`vuln`) is **opt-in and never auto-run**.
- Writes the Stage-2 artifact family: `*.xml`, `*.txt`,
  `*.services.tsv`, `*.services.txt`, `*.status.txt`.
- The Nmap XML is parsed with the **Python standard library**
  (`xml.etree.ElementTree`) — `jq` is not required.
- **Parser fallback is honest**: malformed/truncated XML or a missing `python3`
  falls back to the text artifact and the run is recorded as
  `status=partial` (or `partial-timeout`, `partial-scan-error`,
  `partial-no-parsed-services`); diagnostics are never silently discarded, and
  `*.diagnostics.log` is always preserved.

### Stage 3 — modular service handlers

- `modules/service_handlers/*.sh` enumerate each discovered service. Handlers
  declare which services they `HANDLES` (e.g. `HANDLES="http https"` in
  `http_handler.sh`); a built-in banner extractor (`banner_store_handler.sh`)
  covers every service (`HANDLES="*"`).
- Handlers are **read-only by construction**, each bounded by
  `ENUM_HANDLER_TIMEOUT` (default 30 s), and write into an isolated
  `*.stage3/` directory.
- Every handler result is audited per service in `handlers.tsv`
  (`ok` / `skipped-dependency` / `error`). A handler problem **never fails the
  phase**.

Per-run artifacts are timestamped and never clobbered.

## Artifact selection semantics

Enumeration V2 writes **two distinct artifact families** for one run:

- **Stage 1 — port discovery** (no version data): `*.ports.xml`,
  `*.ports.txt`, `*.ports.nmap.txt`, `*.ports.tsv`.
- **Stage 2 — service/version data**: `*.xml`, `*.txt`, `*.services.tsv`,
  `*.services.txt`, `<run>.status.txt`.

Downstream consumers (Phase 3 `vulnerability.sh`, Phase 7 `report.sh`) must
consume the **Stage-2** artifacts. They therefore use the semantic Stage-2
selection helpers `sat_enum_service_xml` / `sat_enum_service_txt`
(`lib/common.sh`), not a blind "newest matching filename" glob:

- Each run's `*.status.txt` records the authoritative Stage-2 names as
  `enumeration_xml=<basename>` / `enumeration_txt=<basename>`; selectors read
  those, exclude the `*.ports.*` Stage-1 family, and pick the newest run by its
  recorded timestamp.
- For status-less/legacy runs there is a modification-time fallback (never
  lexical order), and the `*.ports.*` family is still never returned.

This is why naive selection is unsafe: `base.ports.xml` sorts before
`base.xml`, so a plain "latest `*.xml`" glob can pick the version-less
Stage-1 file. The semantic selectors guarantee that never happens.

## SearchSploit compatibility

Phase 3 queries SearchSploit with `searchsploit -t ...` (text) and
`searchsploit -t -j ...` (JSON) and parses the JSON into structured candidates.

SearchSploit colour handling is **capability-detected, not version-hardcoded**,
so the module works across exploitdb versions that differ in their
colour-disable option. The probe order actually implemented
(`detect_searchsploit_colour_flag` in `modules/vulnerability.sh`) is:

1. inspect `searchsploit --help` and emit the first present option: `--disable-colour`
   (modern builds) → `--no-colour` → `--colour` (emitted as `--colour=0`);
2. only if none are advertised, confirm `--colour=0` behaviourally with a
   throwaway probe `searchsploit -t --colour=0 ...` — accepted only if it does
   not answer `illegal option|unrecognized option|invalid option`;
3. otherwise emit **no** colour flag.

The detected flag may be overridden via the `SEARCHSPLOIT_COLOUR_FLAG`
environment variable. The module never emits a flag the installed binary
rejects, because a rejected option would make `searchsploit` exit non-zero.

Malformed/usage-error output is **never interpreted as valid exploit
candidates**: JSON is parsed structurally, and rows that cannot be validated
are dropped; a failed or unrecognized run yields zero candidates, not garbage
findings.

## Safety model

- `AUTO_EXPLOIT=false` — candidates are never run automatically.
- `REQUIRE_EXPLOIT_APPROVAL=true` — exploitation always requires an explicit
  interactive `[y/N]` approval inside the run.
- Exploitation is **not** automatically executed by full scans: the phase may
  be *offered* in `--full`/legacy `full`, but each candidate still needs the
  in-run approval; `resume`, `--dry-run`, quick scans, and scope workers never
  invoke it.
- **Denied exploitation is represented honestly** — cancelled/declined exits
  `5`, no session is invented, evidence records `session_status`, and the
  report states "exploitation not performed".
- **Dry runs have no side effects** — no assessment is created and no command
  is executed (network, scans, or exploitation).
- **Worker/process failures never silently become success** — a bounded
  per-target timeout in a scope worker is killed and marked failed
  (`reason=timeout`, aggregate exit `124`); phase statuses come only from real
  outputs.
- **Missing dependencies are handled explicitly** — `status=dependency-missing`
  with exit `3`, never success.
- **Artifacts are isolated** — per assessment, per scope, per target, per run,
  per worker; historical results are never overwritten.

## Exit codes

Per-phase module exit codes (verified from the implementation):

| Code | discovery | enumeration | vulnerabilities | correlation | exploitation | evidence | report |
|---|---|---|---|---|---|---|---|
| 0 | host up | completed (services found; status may say `partial*` — see below) | ok (zero candidates is ok) | ok (zero findings is ok) | session created / ran clean | ok | ok |
| 1 | error | error | error | error | error | error | error |
| 2 | host down | host **unreachable** (scan skipped) | no Stage-2 XML | no data to correlate | ran, no session | no data | no data to report |
| 3 | — | reachable, **zero open ports** (evidence) | missing/disabled dependency | — | missing/disabled dependency | missing dependency | — |
| 4 | — | — | — | — | no candidates or no module mapping | — | — |
| 5 | — | — | — | — | **cancelled/declined by user** | — | — |

Notes:

- Enumeration's `status=partial` / `partial-timeout` / `partial-scan-error` /
  `partial-no-parsed-services` values are recorded in the run's `status.txt`;
  the phase still exits `0` because it completed with artifacts. The nuance is
  never lost: consumers read the status file.
- Multi-phase runs (`scan`, legacy `full`, `resume`) return the failed phase's
  exit code, so a denied/cancelled exploitation surfaces as **5**.
- Scope worker pools return `0` (all targets ok), `2` (≥ 1 target failed), or
  `124` (≥ 1 worker hit the per-target timeout).

## Correlation rules

- **high** — product matches the exploit title AND the detected version
  appears in the title.
- **medium** — product matches AND the title version shares major.minor.
- **low** — product matches, no version evidence in the title.

Severity (`high/medium/low`) is a transparent, categorical tool assessment —
it is **not** an official CVSS score. No CVSS/CVE value is ever manufactured.

## Evidence / session handling

Phase 5 records `session_status` in `result.txt`/`status.txt`:

- `session-created` — a `Meterpreter session N opened` / `Command shell session N
  opened` line was detected in the raw Metasploit output. Phase 6 then extracts
  hostname / user / OS / network evidence from the `sessions -C` output captured
  between the `SAT_HOSTNAME_START` ... `SAT_EVIDENCE_END` markers.
- `no-session` — exploitation ran but produced no session. Recorded honestly.
- `dependency-missing` — Phase 5 could not run.

Exploit candidates come from `config/exploit_mapping.conf` (verified lab
mappings only: `service_key|product_token|version_prefix|msf_module|payload`
with deterministic matching). Unmapped findings are reported but **never
executed**.

## Configuration

`config/config.conf` (every value overridable by exporting an environment
variable of the same name; environment always wins). Test runs override via
`tests/fixtures/config.conf` through `CONFIG_FILE`.

| Variable | Default | Meaning |
|---|---|---|
| `NMAP_TIMING` | `-T4` | Nmap timing |
| `NMAP_PORTS` | `-p-` | Explicit port list/range; an exported `NMAP_PORTS` is honored as `ENUM_PORT_MODE=custom` |
| `NMAP_SERVICE_DETECTION` | `-sV` | Version detection |
| `NMAP_SCRIPTS` | `default` | NSE categories (safe default; `vuln` is opt-in and never auto-run) |
| `NMAP_OUTPUT_FORMAT` | `xml` | Nmap output format |
| `ENUM_PORT_MODE` | `top` | Stage-1 port selection: `top` / `all` / `custom` |
| `ENUM_TOP_PORTS` | `100` | Top-N TCP ports used by `ENUM_PORT_MODE=top` |
| `ENUM_DISCOVERY_TIMEOUT` | `300` | Stage-1 timeout (s), bounded via `timeout` |
| `ENUM_SERVICE_TIMEOUT` | `600` | Stage-2 service-scan timeout (s) |
| `ENUM_HANDLER_TIMEOUT` | `30` | Per-Stage-3-handler timeout (s) |
| `SEARCHSPLOIT_ENABLED` | `true` | Enable Phase 3 lookups |
| `METASPLOIT_ENABLED` | `true` | Enable the Phase 5 runner |
| `AUTO_EXPLOIT` | `false` | Never auto-run candidates |
| `REQUIRE_EXPLOIT_APPROVAL` | `true` | Interactive `[y/N]` approval |
| `SEARCHSPLOIT_COLOUR_FLAG` | *(auto)* | Hard override for the detected colour-disable option |
| `REPORT_FORMAT` | `md,html` | Report output formats |
| `REPORT_TITLE` | `Metasploitable 2 Security Assessment` | Report title |
| `SCOPE_MAX_EXPANDED_TARGETS` | `256` | CIDR expansion cap per range (refusal above this) |
| `ENUMERATION_WORKERS` | `2` | Bounded parallel scope workers (1 = sequential; never unlimited) |
| `SCOPE_TARGET_TIMEOUT` | `300` | Per-target worker timeout (s); expiry is recorded as failed, never success |

Phase 3’s detected SearchSploit colour flag is not persisted as a config
default because it is derived per environment — see
[SearchSploit compatibility](#searchsploit-compatibility).

## Testing

`tests/test_tool.sh` is the deterministic acceptance suite. It runs modules and
the CLI in scratch `tests/runs/<run-ts>/` directories against:

- **Fixtures** — Nmap XML fixtures (`ms2_enum.xml`, `ms2_clean.xml`,
  `corrupt.xml`) and a test `config/config.conf` override.
- **Fake external tools** (`tests/fakes/`) — `nmap`, `searchsploit`, and
  `msfconsole` shims that exercise the tool’s real argument handling, XML
  emission, malformed-output, colour-flag, and approval paths.
- **TEST-NET targets only** (`203.0.113.x`, `198.51.100.x`, `192.0.2.x` — RFC
  5737) — the offline suite never contacts a live host or a real exploitdb /
  Metasploit installation.

Suite properties documented in the harness header:

- **Hermetic**: deterministic inputs, fixed fake datasets, bounded timeouts.
- **Scratch isolation**: per-test logs under `tests/runs/`; scratch output
  roots per test.
- **Cleanup**: run logs and test-produced legacy artifacts are removed on
  completion unless `--keep` is passed; `--verbose` prints the failing test's
  log.
- **Offline vs network-gated**: the offline suite is fully fake-driven. With
  `--network`, four live checks run against `127.0.0.1` (unreachable-host
  handling, no-open-ports handling, open-ports enumeration with real nmap, and
  legacy `all` on an unreachable target). These are genuinely environment-
  dependent: they require loopback scan ports and real `nmap`. Their results
  are therefore not universal guarantees.

Coverage includes the phase pipeline, the single-phase rule, approved/declined
exploitation, assessment isolation and manifest state, `status`, `resume`,
`--dry-run` (zero side effects), `preflight`, corrupt-manifest refusal,
Enumeration V2 (multi-stage, no-open, unreachable, malformed XML fallback, Nmap
failure, missing dependency, port modes, targeted `-sV -sC` on discovered
ports, safe default NSE, denied-approval honesty), the Stage-1/Stage-2 artifact
selection semantics, and SearchSploit colour-flag compatibility across
`modern`/`legacy`/`plain` builds plus malformed-output non-fabrication.

**Verified against this checkout** (the current `tests/test_tool.sh`):
offline suite **270 PASS / 0 FAIL**; with `--network` **275 PASS / 0 FAIL**.
The suite contains environment-dependent checks, so on other hosts the exact
numbers may differ (e.g. loopback ports closed); the harness reports
`PASS/FAIL/SKIP` and failed test names explicitly.

```
./tests/test_tool.sh                       # offline suite (no network)
./tests/test_tool.sh --network --keep      # + live localhost checks, keep logs
```

## Project structure

```
scanner.sh                 unified CLI + legacy single-phase controller
README.md
config/
  config.conf              runtime defaults (see Configuration)
  exploit_mapping.conf     verified lab exploit mappings (Phase 5)
lib/
  common.sh                config, exit codes, validation, artifact selectors
  assessment.sh            assessment IDs, manifest, resume planning
  scope.sh                 scope lifecycle, normalization, CIDR expansion
  scope_worker.sh          bounded per-target worker
  history.py               read-only assessment audit log
  comparison.py            read-only assessment comparison
  target_evidence.py       shared read-only evidence model
modules/
  discovery.sh             Phase 1
  enumeration.sh           Phase 2 (Enumeration V2)
  vulnerability.sh         Phase 3
  correlation.sh           Phase 4
  exploitation.sh          Phase 5
  evidence.sh              Phase 6
  report.sh                Phase 7
  service_handlers/        Phase 2b read-only handlers
    banner_store_handler.sh    (HANDLES="*")
    http_handler.sh            (HANDLES="http https")
output/                    legacy per-phase artifacts (.gitkeep)
output/assessments/        isolated per-assessment runs (manifest + phases)
output/comparisons/        read-only comparison output
reports/                   generated legacy reports (.gitkeep)
tests/
  test_tool.sh             acceptance harness
  fakes/                   fake nmap, searchsploit, msfconsole shims
  fixtures/                XML fixtures + test config override
```

## Known limitations

- **Environment-dependent tests**: the four `--network` checks require live
  loopback scan ports and real `nmap`; offline counts can vary by host.
- **SearchSploit varies across installs**: capability detection widens
  compatibility but a build that advertises none of the detected colour
  options simply runs without a colour flag; findings depend on the locally
  installed exploitdb dataset.
- **Missing dependencies cause explicit partial / failure behavior**: e.g. no
  `searchsploit` → Phase 3 exits `3` (`status=dependency-missing`); no
  `msfconsole` → Phase 5 unavailable. Never silently skipped as success.
- **Correlation is deterministic/rule-based**, so it can contain
  low-confidence findings or noise; severity is the tool's own label, not an
  official CVSS score, and no CVE data is fabricated.
- **Exploitation depends on the verified `exploit_mapping.conf`**; mappings are
  manually maintained for the lab, and unmapped findings are reported but never
  executed.
- **Scope expansion is capped** (`SCOPE_MAX_EXPANDED_TARGETS=256`) to bound
  resource use; scope scans run the non-exploit pipeline per target.
- Enumeration V2 runs NSE `default` (never `vuln` by default) and Stage-2 is
  single Nmap process per run; there is no intra-host stage parallelism.

## Roadmap / V2

Scope management, multi-target incremental scanning (`scope`, `scan <scope_id>`
with `--new/--failed/--all/--targets`), historical comparison (`history`,
`compare`), and bounded parallel scope workers are **implemented in V1.0.0** as
described above.

Future V2 work builds on the current baseline. Things that are **not** part of
V1 and are therefore not claimed here:

- automatic or scheduled exploitation (this is a design invariant, not a gap);
- per-host parallel enumeration inside a single target's stages;
- a web/dashboard UI;
- vulnerability data beyond the local SearchSploit database;
- CVSS scoring or a formal CVE feed.

The retrospective of the original phase roadmap therefore states these as
already-integrated V1 capabilities rather than future promises.

## Examples

```bash
# Help and preflight
./scanner.sh --help
./scanner.sh preflight 192.168.1.6

# New isolated assessments
./scanner.sh scan 192.168.1.6 --quick     # discovery + enumeration only
./scanner.sh scan 192.168.1.6 --full      # full pipeline incl. approval-gated exploitation
./scanner.sh scan 192.168.1.6 --dry-run   # plan only, zero side effects

# Assessment workflow
./scanner.sh status
./scanner.sh status assessment_20260918_064613844783311
./scanner.sh resume assessment_20260918_064613844783311
./scanner.sh resume assessment_20260918_064613844783311 --dry-run
./scanner.sh report assessment_20260918_064613844783311

# Scope-based, incremental, parallel (workers never exploit)
./scanner.sh scope create assessment_20260918_064613844783311 192.168.1.6 192.168.1.7
./scanner.sh scan scope_20260918_065000 --new --workers 2
./scanner.sh scope show scope_20260918_065000
./scanner.sh scope expand scope_20260918_065000 192.168.1.8

# History and read-only comparison
./scanner.sh history
./scanner.sh history assessment_20260918_064613844783311
./scanner.sh compare assessment_A assessment_B

# Legacy single-phase commands (each runs ONLY its phase)
./scanner.sh 192.168.1.6 discovery
./scanner.sh 192.168.1.6 enumeration
./scanner.sh 192.168.1.6 vulnerabilities
./scanner.sh 192.168.1.6 correlation
./scanner.sh 192.168.1.6 exploit        # approval-gated
./scanner.sh 192.168.1.6 evidence
./scanner.sh 192.168.1.6 report
./scanner.sh 192.168.1.6 full
./scanner.sh 192.168.1.6 all
```