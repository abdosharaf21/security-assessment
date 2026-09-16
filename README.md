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
./modules/evidence.sh 192.168.56.101
./modules/report.sh 192.168.56.101
```

## Configuration

`config/config.conf` (override via environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `NMAP_TIMING` | `-T4` | Nmap timing |
| `NMAP_PORTS` | `-p-` | Port selection |
| `NMAP_SERVICE_DETECTION` | `-sV` | Version detection |
| `NMAP_SCRIPTS` | `default,vuln` | NSE scripts |
| `SEARCHSPLOIT_ENABLED` | `true` | Enable Phase 3 lookups |
| `METASPLOIT_ENABLED` | `true` | Enable Phase 5 runner |
| `AUTO_EXPLOIT` | `false` | Never auto-run candidates |
| `REQUIRE_EXPLOIT_APPROVAL` | `true` | Interactive `[y/N]` approval |
| `REPORT_FORMAT` | `md,html` | Report output formats |

`config/exploit_mapping.conf` maps a correlated finding
(`service|product_token|version_prefix|msf_module|payload|notes`) onto a
Metasploit module. Only verified lab mappings are included; unmapped findings
are reported but never executed.

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
lib/common.sh                 shared helpers (config, exit codes, artifact discovery)
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
| 3 | Required dependency missing or disabled |
| 4 | Exploitation only: no candidates or no module mapping |
| 5 | Exploitation only: cancelled/declined by the user |

`scan`/`resume`/`full` return the highest failed-phase exit code; a cancelled or
declined exploitation therefore surfaces as `5`, and the report always records
the honest outcome (e.g. "exploitation not performed").

## Correlation rules

- **high** - product matches the exploit title AND the detected version
  appears in the title.
- **medium** - product matches AND the title version shares major.minor.
- **low** - product matches, no version evidence in the title.

Severity (`high/medium/low`) is a transparent, categorical tool assessment -
it is **not** an official CVSS score. No CVSS/CVE value is ever manufactured.

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
has zero side effects), `preflight`, dry-run planning, and corrupt-manifest
refusal.

```
./tests/test_tool.sh                      # offline suite (no network)
./tests/test_tool.sh --network --keep     # + live localhost enumeration checks
```

`--verbose` prints the relevant log for a failing check. Run logs are kept under
`tests/runs/` only when `--keep` is passed.