# Requirements

This page lists what UCFM supports and what it needs to run.

## Supported deployments

| | Supported |
|---|---|
| Products | MongoDB Community, MongoDB Enterprise, Percona Server for MongoDB |
| Versions | 6.0, 7.0, 8.0, 8.3, 9.0, as running versions and as upgrade targets |
| Topologies | Standalone, replica set, sharded cluster |

> [!NOTE]
> Percona Server for MongoDB 9.0 is not released yet. For Percona Server for MongoDB deployments, upgrade steps to 9.0 are checked against MongoDB Community 9.0, and the report says so.

## Where to run UCFM

- **Any Linux host that can reach the deployment.** UCFM connects to the node in `--uri`, then to every replica set member, shard, config server and mongos it discovers. If some of them are not reachable, use `--entry-only` to check only the node in `--uri`.
- **On each database host, for host checks.** `--local` reads kernel, filesystem and limit settings from the machine UCFM runs on. See [Host checks](../usage/host-checks.md).

## Database user

UCFM only runs read commands. This user collects everything it needs:

```js
use admin
db.createRole({
  role: "ucfmViewSecurity",
  privileges: [
    { resource: { cluster: true },          actions: ["viewUser"] },
    { resource: { db: "", collection: "" }, actions: ["viewUser", "viewRole"] },
    { resource: { db: "", collection: "system.views" }, actions: ["find"] }
  ],
  roles: []
})
db.createUser({
  user: "ucfm",
  pwd: passwordPrompt(),
  roles: ["clusterMonitor", "readAnyDatabase", "ucfmViewSecurity"]
})
```

> [!IMPORTANT]
> **Sharded clusters:** create the user twice, through a mongos (it is stored on the config servers) **and on the primary of every shard**. ucfm also connects to shard members directly, and those only accept shard-local users.

| Role | Used for |
|---|---|
| `clusterMonitor` | Versions, options, parameters, replica set and sharding state, server status, oplog |
| `readAnyDatabase` | Collections, views, validators and indexes; profiler entries; document samples with `--deep-check` |
| `ucfmViewSecurity` | Users and custom roles, and view definitions in `system.views` (views on `system.buckets` are not returned by `listCollections`); without it those checks are skipped |

Anything UCFM could not read is reported under `collection-gaps` (`prod-collection-gaps` in the audit), so a partial check is always visible.

## Load on the deployment

UCFM is built to run against production:

- It sends only read commands.
- Every command has a time limit that the server enforces (`maxTimeMS`), 60 seconds by default. If a command takes too long, the server stops it, not only the client.
- On a replica set, the catalog reads go to a secondary when one is available: database, collection and index listings, view definitions, users and roles, and the `--deep-check` sample. Members more than 90 seconds behind are skipped. Reads that describe one node stay on that node: `serverStatus`, `$currentOp`, the profiler and the oplog. Sharding metadata is read from the primary.
- `--deep-check` reads up to 1000 documents per collection. Leave it out to read no documents.

## Next steps

- [Install UCFM](installation.md)
