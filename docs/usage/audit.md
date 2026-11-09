# Audit production settings

`ucfm audit` compares the running deployment with the MongoDB [Production Notes](https://www.mongodb.com/docs/manual/administration/production-notes/) and [Operations Checklist](https://www.mongodb.com/docs/manual/administration/production-checklist-operations/).

```bash
ucfm audit --uri "mongodb://ucfm@db1:27017/?authSource=admin"
ucfm audit --uri "mongodb://ucfm@localhost:27017/?authSource=admin" --local   # on a database host
```

The audit is separate from the upgrade check. It needs no `--target` and judges the version you run now. It never changes the findings or the exit code of `ucfm check`.

## What is checked

| Area | Checks |
|---|---|
| Host (`--local`) | THP for the running version, swappiness, NUMA, dbPath filesystem and `noatime`, readahead, I/O scheduler, open-files and process limits, kernel limits, clock sync, TCP keepalive, free disk space, SELinux with server-side JavaScript |
| Platform | Operating system supported by the running release (Red Hat family, Debian, Ubuntu), Oracle UEK kernel, CPU cores |
| Deployment | Access control, TLS, voting members, hostnames instead of IP addresses, identical members, journaling, WiredTiger cache size, oplog window, connection usage |
| Manual review | One notice for items no tool can verify: RAID and storage, monitoring, backups, antivirus exclusions, load balancers, data-center layout, security checklist |

Findings are `WARNING` or `NOTICE` only. The exit code is `1` when there are warnings and `0` otherwise.

A setting that meets the recommendation is reported with what was checked, for example `No issues found: the oplog covers 41 hours on every member (minimum 24).`

## In the upgrade report

```bash
ucfm check --uri ... --target 8.0 --with-audit
```

This appends the audit as its own section (an `audit` key in JSON). The exit code still reflects the upgrade check only.

> [!NOTE]
> THP is judged against the version you run now: disabled before 8.0, enabled from 8.0. The upgrade check separately tells you when the recommendation changes on the way to 8.0.

## Next steps

- [Host checks](host-checks.md)
- [Rules](../reference/rules.md)
