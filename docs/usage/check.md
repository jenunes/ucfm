# Check upgrade readiness

`ucfm check` reports what you must handle before upgrading to a target version.

```bash
ucfm check --uri "mongodb://ucfm@db1:27017/?authSource=admin" --target 8.0
```

## Upgrade path

You give the final target; UCFM works out the version steps. A release can only start on data whose featureCompatibilityVersion (FCV) is its previous LTS or previous release:

| From | To | Path |
|---|---|---|
| 6.0 | 8.0 | 6.0 → 7.0 → 8.0 |
| 6.0 | 9.0 | 6.0 → 7.0 → 8.0 → 9.0 |
| 7.0 | 8.3 | 7.0 → 8.0 → 8.3 |
| 8.0 | 9.0 | 8.0 → 9.0 |
| 8.3 | 9.0 | 8.3 → 9.0 |

UCFM checks one major upgrade at a time. When the target is one step away, check 1 confirms the path. When it is more steps away, UCFM checks the next step only, check 1 reports an error with the full path, and the exit code is 2. After that upgrade, run UCFM again against the upgraded deployment for the next step. The later steps depend on settings, FCV and data that do not exist yet, so checking them now would be a guess.

## What is checked

## Reading the report

Every check follows the same pattern, so you can scan by number, rule ID or status:

```text
N) Title (rule-id)
   Status: what was found or checked, wrapped with a 3-space hanging indent

   - affected item

   Solution:
   - what to do
        command to copy (never wrapped)

   More information:
     https://...
```

- The status is one of `No issues found: <what was checked>`, `Not applicable: <why>`, `Not checked: <what to enable>`, or `Error:`, `Warning:`, `Notice:`.
- A `====` banner opens each section: deployment-wide checks, then each upgrade step with the release catalog it was checked against.
- The report ends with the counts and the checks with errors or warnings, by number and rule ID.

- **Deployment-wide:**
  - featureCompatibilityVersion and mixed versions
  - replica set health and lag
  - arbiters
  - balancer, migrations and resharding
  - startup warnings and connected drivers
- **Each step:**
  - startup options, server parameters, commands, custom-role actions and aggregation operators that the target removes or renames
  - documented compatibility changes for that step (for example THP and the kernel requirements for 8.0, and Queryable Encryption changes)
  - the operating system of every host against the target's official supported list: Red Hat (RHEL, and Rocky, Alma and Oracle Linux by RHEL version), Debian and Ubuntu, for x86_64 and arm64

The full list is in [Rules](../reference/rules.md).

## How behavior changes are verified

Documented behavior changes are checked against the deployment, one check each, using:

| Evidence | What it shows | Needs |
|---|---|---|
| Server counters | Which operators, aggregation stages and commands the applications ran since each server started (for example `$add`, `$dateAdd`, `$changeStream`, `compact`, hedged reads) | Nothing. Always read. |
| Server state | Settings, indexes, collections and connections (chunk size, 2dsphere indexes, `system.buckets` collections, application connections to shard members) | Nothing. Always read. |
| Profiler | Query shapes such as `$natural` hints and matches on `null`. Literal values are removed. | The profiler enabled on the application databases |
| Document sample | Stored values whose behavior changes, such as the deprecated BSON `undefined` type | `--deep-check` |

When evidence is missing, the check says what to enable instead of guessing.

> [!NOTE]
> Counters restart with each server, and the report shows the window ("since startup 4 days ago"). A feature used rarely, such as a monthly job, may not appear after a recent restart.

## Reports

```bash
ucfm check --uri ... --target 9.0                          # text (default)
ucfm check --uri ... --target 9.0 --format json -o report.json
ucfm check --uri ... --target 9.0 --format md   -o report.md
ucfm check --uri ... --target 9.0 --with-audit             # add the production audit
ucfm check --uri ... --target 9.0 --issues-only            # hide checks with no issues
ucfm check --uri ... --target 8.0 --deep-check             # also sample documents
```

The JSON report starts with `"schemaVersion": 1`. The number changes only when a field is removed or changes meaning; new fields can appear without a change. `ucfm audit --format json` carries the same field.

| Exit code | Meaning |
|---|---|
| 0 | No warnings or errors |
| 1 | Warnings, no errors |
| 2 | At least one error: correct it before upgrading |
| 3 | UCFM itself failed (connection, options) |

> [!TIP]
> Add `--local` when you run UCFM on a database server. It also checks the host (THP, kernel, glibc) for the upgrade. See [Host checks](host-checks.md).

## Next steps

- [Commands and options](../reference/commands.md)
