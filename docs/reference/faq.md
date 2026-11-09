# FAQ and troubleshooting

### Does UCFM change anything on my deployment?

No. It only runs read commands and reads host files. The only things it writes are the reports and snapshots you ask for.

### Do the database servers need Go?

No. Install the static binary with the one-line installer, download it from a release, or build it once with `make dist` on another machine and copy it. See [Installation](../getting-started/installation.md).

### I ran --local on my workstation, not on the database host. Are its settings checked?

No. ucfm recognizes that the machine is not a member of the deployment and ignores its settings. The host checks are reported as not checked, and the report lists the command to run on each database host. See [Host checks](../usage/host-checks.md#running-ucfm-from-another-machine).

### Which operating systems are supported?

Red Hat Enterprise Linux (with Rocky Linux, AlmaLinux and Oracle Linux judged by their RHEL version), Debian and Ubuntu, on the versions MongoDB and Percona officially support for each release. Any other OS, or an older version, is reported as a `WARNING`, with the supported list and its source. Where no official list exists (Percona Server for MongoDB 6.0 and 9.0), the check reports "not checked".

### Why does a 6.0 → 9.0 check only cover 6.0 → 7.0?

Each release starts only on data from its previous LTS release or its previous release, so 6.0 goes through 7.0 and 8.0 before 9.0. UCFM checks one upgrade at a time: after 6.0 → 7.0 the deployment has a new FCV, new defaults and maybe new settings, and the 7.0 → 8.0 check must look at that deployment, not at a guess. Check 1 reports the full path as an error so the remaining steps are not forgotten. See [How it works](how-it-works.md#2-plan).

### Some members are unreachable from where I run UCFM

UCFM connects to the members using the host names stored in the replica set and sharding configuration. Run it from a host that can resolve and reach those names, or use `--entry-only` to check only the node in `--uri`. Unreachable members are listed under `collection-gaps`.

### ucfm says the login was rejected on some shards

On a sharded cluster ucfm also logs in to every shard member, and shard members only accept users created on the shard itself. Users created through mongos are stored on the config servers. Create the same user, with the same roles, on the primary of each shard; see [Requirements](../getting-started/requirements.md#database-user). Until then, the "Access to every shard" check lists the shards that were skipped.

### The report shows `collection-gaps`

Some facts could not be read, usually because of missing privileges, unreachable members or unreadable host files. The checks that depend on them are incomplete. Create the user from [Requirements](../getting-started/requirements.md#database-user) and re-run.

### I run Percona Server for MongoDB and target 9.0

Percona Server for MongoDB 9.0 is not released yet, so the step to 9.0 is checked against MongoDB Community 9.0. Options that exist only in Percona Server for MongoDB get a `WARNING` that asks you to verify them, instead of an `ERROR`.

### The check says enable THP but the audit says disable it

Both are right. The audit judges the version you run now: before 8.0, THP should be disabled. The check tells you what to change for the target: from 8.0, THP should be enabled. Switch THP when you move to 8.0 binaries.

### Can I check a deployment I can't connect to from my workstation?

Yes. Run `ucfm collect` on a host that can reach it, copy the snapshot, and analyze it anywhere. See [Snapshots](../usage/snapshots.md).

### How do I see every rule?

Run `ucfm list-rules`, or see [Rules](rules.md).

### How do I keep the password out of ps and the shell history?

Leave the password out of `--uri` and UCFM asks for it, or put the connection string in the `UCFM_URI` environment variable or in a file given with `--uri-file`. See [Commands and options](commands.md#keeping-the-password-off-the-command-line).
