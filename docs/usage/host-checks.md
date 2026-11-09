# Host checks

With `--local`, UCFM also reads settings from the machine it runs on. Run it on each database server.

```bash
ucfm check --uri "mongodb://ucfm@localhost:27017/?authSource=admin" --target 8.0 --local
ucfm audit --uri "mongodb://ucfm@localhost:27017/?authSource=admin" --local
```

`--local` works with `check`, `audit` and `collect`. It is Linux only.

`check` and `audit` use the host settings for different questions:

| Command | Host settings checked |
|---|---|
| `check --local` | Only those the target release requires: THP for 8.0 and later, the kernel for the new TCMalloc, glibc rseq, and the supported operating systems |
| `audit --local` | The full production checklist: swappiness, readahead, limits, filesystem, noatime, NUMA, clock, TCP and more |

`check --local --with-audit` gives both in one report. Without `--with-audit`, `check --local` reminds you of it on standard error.

## Running ucfm from another machine

`--local` only reads the machine ucfm runs on. ucfm compares that machine's host names and addresses with the deployment's members:

- **It is a member:** its settings are checked and reported under that member's name, for example `node1 (172.21.0.3:27017)`.
- **It is not a member** (a workstation or jump host): its settings are never used. ucfm prints a warning, reports the host checks as not checked, and lists the command to run on each database host.

```text
ucfm: warning: this machine (laptop) is not a host of this deployment; its OS settings will not be used. Run ucfm with --local on each database host.
```

One run checks one host. To check every host, run the commands from **Host checks coverage** on each of them.

## When you didn't use --local

Every report ends its deployment-wide checks with **Host checks coverage**. It lists each database host whose settings were not checked, with the exact command to run there, built from your connection string without the password, which UCFM asks for when you run it:

```text
14) Host checks coverage (host-checks-coverage)
   Notice: Operating system settings (Transparent Huge Pages, kernel, glibc,
      limits, filesystem, NUMA, clock) were not checked: ucfm reads them only
      when it runs on the database host with --local. The servers logged 1
      startup warning about the operating system.

   - db2:27017

   Solution:
   - Copy ucfm to each host and run the command for it; ucfm asks for the
      password:
        ucfm check --uri "mongodb://ucfm@db2:27017/?authSource=admin&directConnection=true" --target 8.0 --local --entry-only
```

Server startup warnings about the operating system (THP, ulimits, NUMA, filesystem, glibc) also name the host check that covers them.

## What is read

| Area | Source |
|---|---|
| OS and kernel | `/etc/os-release`, kernel release |
| Transparent Huge Pages | `enabled`, `defrag`, `khugepaged/max_ptes_none` |
| Kernel settings | swappiness, zone_reclaim_mode, max_map_count, file-max, pid_max, threads-max, TCP keepalive and retries |
| mongod processes | Command line, `GLIBC_TUNABLES`, open-files and process limits, NUMA interleave |
| Configuration file | The mongod.conf a running mongod uses, `/etc/mongod.conf`, or the file passed with `--config` |
| dbPath storage | Filesystem type, mount options, readahead, I/O scheduler, free space |
| Other | glibc version, CPU flags, NUMA nodes, clock synchronization, SELinux mode, cgroup memory limit |

Options set in the configuration file are checked together with those reported by the running server. A removed option is caught even if mongod has not been restarted since it was added.

> [!TIP]
> To read the environment and limits of a mongod owned by another user, run UCFM as that user or as root. Host files that cannot be read are listed under `collection-gaps`; values that cannot be read are skipped, never guessed.

## Next steps

- [Audit production settings](audit.md)
- [Snapshots](snapshots.md): collect host facts on each server and analyze them in one place
