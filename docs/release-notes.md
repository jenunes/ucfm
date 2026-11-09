# Release notes

## 1.0.0 (2026-11-09)

First release. UCFM is open source under the [Apache License 2.0](../LICENSE).

Commands:
- `ucfm check`: upgrade readiness for MongoDB Community, Enterprise and Percona Server for MongoDB 6.0, 7.0, 8.0, 8.3 and 9.0, on standalone servers, replica sets and sharded clusters. It works out the upgrade path and checks the next upgrade step.
- `ucfm audit`: deviations from the MongoDB Production Notes and Operations Checklist.
- `ucfm collect` and `--from-snapshot`: collect once, analyze anywhere.
- One major upgrade at a time: when `--target` is more than one upgrade away, `check` covers the next step only, and check 1 reports an error with the full path and a link to that step's official upgrade procedure (exit code 2).
- `--local`: host checks (THP, kernel, glibc, limits, filesystem, NUMA, clock, supported operating systems).

Checks:
- Catalog rules generated from the server source code of each release: startup options, server parameters, commands, privilege actions and aggregation operators.
- Documented-change rules from the MongoDB and Percona release notes, each with a documentation link.
- Documented behavior changes are checked against evidence from the deployment: operator and aggregation stage counters, mongos hedging metrics, the profiler, and a document sample with `--deep-check`.
- Views on `system.buckets` are found even though `listCollections` hides them.
- Time series collections sharded on their timeField (deprecated in 8.0).
- The TCMalloc per-CPU cache state, read from `serverStatus` on 8.0 and later.
- Application drivers connected to every replica set member and shard (from `$currentOp`), listed with their applications and hosts so they can be checked against the driver compatibility matrix of the target release.
- Supported operating systems against the official lists for Red Hat Enterprise Linux and rebuilds, Debian and Ubuntu.
- On sharded clusters, a warning when UCFM cannot log in to a shard because the user exists only through mongos.
- Settings of a machine that is not a deployment member are never reported as the deployment's. A notice lists the hosts whose operating system was not checked, with the `--local` command to run on each one.

Reports:
- The text report follows the MySQL Shell upgrade checker. Every check has the same shape: `N) Title (rule-id)`, the status first (`No issues found`, `Not applicable`, `Not checked`, `Error`, `Warning` or `Notice`), affected items as bullets, a `Solution` with commands on their own lines for copying, and `More information` links. Banners open each section, and the report closes with the counts and the checks to act on. The report never says an upgrade is blocked; it says what will fail or change.
- A check that passes says what it looked at, for example "No issues found: FCV is 8.0 on 3 members, the same as their binaries."
- Text, JSON and Markdown formats. JSON reports start with `"schemaVersion": 1` and carry the planned path (`plannedPath`, `checkedTarget`), a `summary` for each passing check, `docUrls` when a finding has several links, and `commands` for command lines to copy.
- Exit codes for scripting: 0 no warnings or errors, 1 warnings, 2 errors, 3 tool failure.

Other:
- One-line installer that always installs the latest release.
- Built for production: every read has a time limit the server enforces (`maxTimeMS`), and on a replica set the catalog reads and the `--deep-check` sample go to a secondary when one is available.
- The password can stay off the command line: UCFM asks for it when `--uri` has none, and reads the connection string from `UCFM_URI` or `--uri-file`. The commands it prints for host checks carry no password.
- Options given without a command (`ucfm --uri ...`) get an error that shows where the command goes. `check --local` without `--with-audit` notes on standard error that the full host checklist is in `ucfm audit --local`.
- Tested on real replica sets and 3-shard clusters of every supported version, with each detectable change planted and reported.
