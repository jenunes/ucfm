# Quick start

Run your first upgrade check in three steps. [Install UCFM](installation.md) first; the database servers don't need Go.

## 1. Create the database user

Create the read-only `ucfm` user described in [Requirements](requirements.md#database-user).

## 2. Run the check

Point `--uri` at any replica set member, or at a mongos for a sharded cluster, and choose the target version:

```bash
ucfm check --uri "mongodb://ucfm@db1:27017/?authSource=admin" --target 8.0
```

UCFM discovers the rest of the deployment, works out the upgrade path (for example 6.0 → 7.0 → 8.0), and checks the next step. Run it again after each upgrade.

## 3. Read the report

Findings are grouped into deployment-wide checks and one section per upgrade step:

| Severity | Meaning |
|---|---|
| `ERROR` | The upgrade will fail or break something. Correct it before upgrading. |
| `WARNING` | A behavior change or risk. Review it and decide. |
| `NOTICE` | Information. No action is required. |

Every check is numbered and reports `No issues found`, `Not applicable`, how to make it run (for example `--local`), or its findings. Each finding names the affected hosts or objects, the action to take and a link to the documentation. The report ends with the number of errors, warnings and notices. The exit code is `2` when there are errors, `1` for warnings only, `3` when UCFM itself fails, and `0` otherwise.

## Next steps

- [Audit production settings](../usage/audit.md)
- [Host checks](../usage/host-checks.md) on each database server
