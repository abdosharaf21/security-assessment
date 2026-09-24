# Security Assessment Tool (Bash)

A modular, evidence-first security assessment pipeline for the **authorized
Metasploitable 2 lab target only**. Every phase produces artifacts that are
stored under `output/`; nothing is fabricated - if a phase could not run, or
did not find anything, the tool says so.

## Scope and safety

- Designed for the **Metasploitable 2** lab target on an isolated network.
- The target is **user-supplied** and validated (no option injection, no shell
  metacharacters, no whitespace). No IP is hardcoded.
- Exploitation is **approval-gated** (`AUTO_EXPLOIT=false`,
  `REQUIRE_EXPLOIT_APPROVAL=true` by default). It is never run automatically by
  `scan`, `resume`, or `--dry-run`; only an explicit command or the `full`
  pipeline can run it, and always after an interactive in-run approval.
- No CVE/CVSS data is fabricated. Confidence and severity are the tool's own
  deterministic, documented rules.

## Requirements

- `bash` 4+
- `nmap`
- `python3`
- `searchsploit` (exploitdb) - Phase 3
- `msfconsole` (Metasploit) - Phase 5, lab-only

Phases 1-2 work without `searchsploit`/`msfconsole`. When a late-phase
dependency is missing the phase records `status=dependency-missing` and exits
with code `3`.

## Usage

Every legacy phase command runs **only that single phase** - nothing is chained
after it. The full pipeline runs every phase in order and only runs exploitation
after an explicit in-run approval.

```
# Unified CLI
./scanner.sh scan <target> [--quick|--full|--dry-run]   # new isolated assessment;
                                                       # --quick = discovery+enumeration
                                                       # --full  = full pipeline (exploit gated)
./scanner.sh status [<assessment-id>]                  # list or detailed state
./scanner.sh resume <assessment-id> [--dry-run]        # skip done, retry failed, never auto-exploit
./scanner.sh report <assessment-id>                    # (re)generate an assessment report
./scanner.sh preflight [<target>]                      # tool/config/writability/reachability
./scanner.sh menu                                      # interactive main menu
./scanner.sh --help

# Legacy single-phase commands (each runs ONLY its phase)
./scanner.sh <target> discovery          # Phase 1  host discovery
./scanner.sh <target> enumeration        # Phase 2  service enumeration (sudo for -O)
./scanner.sh <target> vulnerabilities    # Phase 3  SearchSploit research
./scanner.sh <target> correlation        # Phase 4  finding correlation / risk
./scanner.sh <target> exploit            # Phase 5  exploitation ONLY (approval-gated)
./scanner.sh <target> evidence           # Phase 6  evidence / session handling
./scanner.sh <target> report             # Phase 7  report generation
./scanner.sh <target> full               # discovery -> enumeration -> vulnerabilities ->
                                         # correlation -> exploitation [approval REQUIRED] ->
                                         # evidence -> report
./scanner.sh <target> all                # discovery + enumeration only
```

Each phase can also be run standalone, e.g.:

```
./modules/enumeration.sh 192.168.56.101
sudo ./modules/enumeration.sh 192.168.56.101   # enables OS detection
./modules/vulnerability.sh 192.168.56.101
./modules/correlation.sh 192.168.56.101
./modules/exploitation.sh 192.168.56.101       # interactive selection + approval
./modules/exploitation.sh 192.168.56.101 <corr_dir> 2        # direct candidate 2
./modules/exploitation.sh 192.168.56.101 --risk high         # filter: high risk only
./modules/exploitation.sh 192.168.56.101 --port 139          # filter: port 139
./modules/exploitation.sh 192.168.56.101 --edb-id 16320      # filter: EDB-16320
./modules/evidence.sh 192.168.56.101
./modules/report.sh 192.168.56.101
```

## Configuration

`config/config.conf` (override via environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `NMAP_TIMING` | `-T4` | Nmap timing |
| `ENUM_PORT_MODE` | `top` | Enumeration V2 stage-1 port selection: `top` (top-N), `all` (`-p-`), `custom` (`NMAP_PORTS`) |
| `ENUM_TOP_PORTS` | `100` | Number of top ports used by `ENUM_PORT_MODE=top` |
| `NMAP_PORTS` | `-p-` | Explicit port list/range; an exported `NMAP_PORTS` is always honored as `custom` |
| `NMAP_SERVICE_DETECTION` | `-sV` | Version detection |
| `NMAP_SCRIPTS` | `default` | NSE scripts (safe default; `vuln` is opt-in and never auto-run) |
| `ENUM_DISCOVERY_TIMEOUT` | `300` | Stage-1 timeout (seconds, bounded via `timeout`) |
| `ENUM_SERVICE_TIMEOUT` | `600` | Stage-2 timeout (seconds) |
| `ENUM_HANDLER_TIMEOUT` | `30` | Per-stage-3-handler timeout (seconds) |
| `SEARCHSPLOIT_ENABLED` | `true` | Enable Phase 3 lookups |
| `METASPLOIT_ENABLED` | `true` | Enable Phase 5 runner |
| `AUTO_EXPLOIT` | `false` | Never auto-run candidates |
| `REQUIRE_EXPLOIT_APPROVAL` | `true` | Interactive `[y/N]` approval |
| `MFE_FILTER_THRESHOLD` | `50` | Show the interactive filter menu when more candidates than this are listed |
| `REPORT_FORMAT` | `md,html` | Report output formats |

`config/exploit_mapping.conf` maps a correlated finding
(`service|product_token|version_prefix|msf_module|payload|notes`) onto a
Metasploit module. Only verified lab mappings are included; unmapped findings
are reported but never executed.

## Enumeration V2 (Phase 2)

Phase 2 is a three-stage pipeline with evidence-first behavior:

1. **Stage 1 - Port discovery** (`nmap -T4 -Pn -n -sT --max-retries 1 ...`)
   selects ports per `ENUM_PORT_MODE` (top-N / all / custom). A host that
   answers no probe is reported `unreachable` and the expensive scan is never
   started (`exit 2`). A reachable host with zero open ports is a valid,
   evidence-based result (`exit 3`), never retried.
2. **Stage 2 - Targeted service enumeration** runs `-sV` + NSE `default`
   (`-sC` equivalent) **only against the discovered ports**, with OS detection
   (`-O`) when run as root. The Nmap XML is parsed with the Python standard
   library (`xml.etree.ElementTree`); malformed/truncated XML or a missing
   `python3` falls back to the text artifact and the run is recorded honestly
   as `status=partial` - diagnostics are never silently discarded.
3. **Stage 3 - Modular service handlers** (`modules/service_handlers/*.sh`)
   enumerate each service. Handlers declare which services they `HANDLES`
   (e.g. `HANDLES="http https"`); a built-in banner extractor plus an
   HTTP(S) reader are included. Handlers are **read-only by construction**,
   bounded by `ENUM_HANDLER_TIMEOUT`, and record
   `skipped-dependency`/`error`/`ok` per service in `handlers.tsv` - a handler
   problem never fails the phase.

Per-run artifacts (never clobbered, timestamped): `*.ports.nmap.txt`,
`*.ports.txt`, `*.ports.tsv`, `*.ports.xml`, `*.txt`, `*.xml`,
`*.services.tsv`, `*.services.txt`, `*.status.txt`, `*.diagnostics.log`, and a
`*.stage3/` directory. `report.sh` and Phase 3 consume the latest `*.txt` /
`*.xml` as before.

## Architecture

```
scanner.sh                    controller (unified CLI + legacy dispatch)
lib/assessment.sh             assessment manager (IDs, manifest, resume plan)
  modules/discovery.sh        Phase 1
  modules/enumeration.sh      Phase 2
  modules/vulnerability.sh    Phase 3  (XML -> Nmap services -> SearchSploit)
  modules/correlation.sh      Phase 4  (deterministic confidence + severity)
  modules/exploitation.sh     Phase 5  (mapping, resource script, session detect)
modules/evidence.sh         Phase 6  (honest session/evidence record)
  modules/report.sh           Phase 7  (Markdown + HTML)
  modules/service_handlers/   Phase 2b (read-only service handlers, opt-in)
  lib/common.sh               shared helpers (config, exit codes, artifact discovery)
config/                       config.conf, exploit_mapping.conf
output/                       per-phase artifacts per target
output/assessments/           per-assessment isolated runs (manifest.json + phases)
reports/                      generated reports
tests/                        test harness + fixtures + fake external tools
```

Artifacts are written under `output/<phase>/<safe_target>_<timestamp>/` so
repeated runs never clobber earlier results. Nmap XML is the structured input;
a Python stdlib parser converts it to TSV/JSON. `jq` is not required.

`scan`/`resume` isolate each run under `output/assessments/<id>/` and record a
`manifest.json` (status, `completed_phases`, `failed_phases`) that is only ever
updated from real phase outcomes; missing/corrupt manifests are refused rather
than fabricated. `status` shows the on-disk state per phase.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (findings may be zero - see `summary.txt`) |
| 1 | Usage / configuration / technical error |
| 2 | No relevant data (host down, no XML, no session, no findings) |
| 3 | Required dependency missing or disabled; enumeration: host reachable but zero open ports |
| 4 | Exploitation only: no candidates or no module mapping |
| 5 | Exploitation only: cancelled/declined by the user |

`scan`/`resume`/`full` return the highest failed-phase exit code; a cancelled or
declined exploitation therefore surfaces as `5`, and the report always records
the honest outcome (e.g. "exploitation not performed").

## Correlation rules

Correlation is evidence-based and deterministic. Every candidate carries a
`match_type`, an `evidence_confidence` and a `severity` (`severity` is the
tool's categorical assessment - it is **not** an official CVSS score; no
CVE/CVSS value is ever manufactured).

| match_type | Meaning | Confidence | Severity |
|---|---|---|---|
| `EXACT_VERSION_MATCH` | detected version equals the title's version | high | high (remote/webapp) |
| `VERSION_RANGE_MATCH` | detected version falls inside the title's range (`3.0.20 < 3.0.25rc3`) | medium | medium |
| `STRONG_PRODUCT_SERVICE_MATCH` | product family + specific component both match (e.g. `Apache` + `Jserv`) | medium | medium |
| `PRODUCT_MATCH_ONLY` | product matches, no comparable version in the title | low | low |
| `VERSION_UNKNOWN` | detected version is generic/unknown (e.g. `3.X - 4.X`) | low | low |
| `VERSION_CONFLICT` | detected version contradicts the title statement | low | low |
| `VENDOR_ONLY_MATCH` | only a generic vendor word matched (e.g. `Apache` for `Apache Tomcat`) | low | low |

Two rules that fix common false positives:

- A SearchSploit entry for `Samba 2.2.x` is **not** a high-confidence finding
  for a host whose service reports `Samba smbd 3.X - 4.X` (an exact version is
  required for `high`; a generic detected version is `VERSION_UNKNOWN`/`low`).
- A candidate that shares only a generic vendor word with the detected product
  (`Apache Tomcat`/`Apache Struts`/`Apache Spark` vs. `Apache Jserv`) is a
  vendor-only, low-confidence reference - it ranks below the specific
  `Apache Jserv` match.

## Exploitation (Phase 5)

- Candidates are listed in deterministic order (match type, then risk, then
  confidence, then port/EDB). A candidate with **no configured mapping is
  reported before any approval prompt and is never executed** (exit `4`) -
  approval is only ever asked for an action that can actually run.
- Selection is interactive (`[n]`), or non-interactive via a positional
  `candidate_index` or `AUTO_EXPLOIT` (still approval-gated).
- Filters narrow the list before selection: `--risk <high|medium|low>`,
  `--port <port>`, `--edb-id <id>` (also forwarded through
  `scanner.sh <target> exploit --risk ...`).
- A large candidate list (> `MFE_FILTER_THRESHOLD`) offers an interactive
  filter menu before selection instead of one long numbered list.

## Evidence / session handling

Phase 5 records `session_status` in `result.txt`/`status.txt`:

- `session-created` - a `Meterpreter session N opened` / `Command shell session N
  opened` line was detected in the raw Metasploit output; Phase 6 then extracts
  hostname / user / OS / network evidence from the `sessions -C` output captured
  between the `SAT_HOSTNAME_START` ... `SAT_EVIDENCE_END` markers.
- `no-session` - exploitation ran but produced no session. Recorded honestly.
- `dependency-missing` - Phase 5 could not run.

## Testing

`tests/test_tool.sh` runs deterministic checks against fixtures and **fake**
`nmap`/`searchsploit`/`msfconsole` shims - no real external tools or live hosts
are required for the offline suite. The suite covers the phase pipeline plus the
single-phase rule (a `discovery|...|exploit|evidence|report` command runs only
that phase; only `full` chains the pipeline and only after a gated approval),
assessment isolation/manifest state, `status`, `resume` (skip/retry, `--dry-run`
has zero side effects), `preflight`, dry-run planning, corrupt-manifest
refusal, and Enumeration V2 (normal multi-stage run, no-open reachable host,
malformed XML fallback, Nmap failure, missing dependency, port-selection modes,
targeted `-sV -sC` on discovered ports, safe default NSE, and denied-approval
full-scan honesty).

```
./tests/test_tool.sh                      # offline suite (no network)
./tests/test_tool.sh --network --keep     # + live localhost enumeration checks
```

`--verbose` prints the relevant log for a failing check. Run logs are kept under
`tests/runs/` only when `--keep` is passed.