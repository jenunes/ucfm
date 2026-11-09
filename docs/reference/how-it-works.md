# How it works

UCFM works in three stages: collect, plan, check.

## 1. Collect

UCFM connects to the node in `--uri` and discovers the rest of the deployment:

- **Replica set:** every member, using `replSetGetStatus` and `replSetGetConfig`.
- **Sharded cluster:** the config server replica set (from the mongos options), every shard from `listShards`, and every mongos that has pinged recently from `config.mongos`.

From each member it reads only, with read commands such as `hello`, `buildInfo`, `getCmdLineOpts`, `getParameter`, `serverStatus`, `getLog` and `hostInfo`:
- version, featureCompatibilityVersion, startup options and parameters
- command counters, connections, the oplog window, TCMalloc per-CPU cache state and startup warnings

Through the entry node it lists:
- collections, views, validators and indexes
- users and custom roles
- connected drivers, from `$currentOp`
- sharding state: balancer, migrations, resharding, and the shard key of each sharded collection

With `--local` it adds host settings (see [Host checks](../usage/host-checks.md)). Everything goes into a [snapshot](../usage/snapshots.md).

Every read has a server-side time limit, and catalog reads on a replica set prefer a secondary. See [Load on the deployment](../getting-started/requirements.md#load-on-the-deployment).

## 2. Plan

A MongoDB binary starts only on data whose featureCompatibilityVersion is its previous LTS release or its previous release. UCFM reads these rules for each version and finds the shortest valid path through the supported versions. For example, 6.0 → 9.0 becomes 6.0 → 7.0 → 8.0 → 9.0, and 8.0 → 9.0 is a single step. Only the next step is checked, against its own target version; the later ones are checked on a later run, against the upgraded deployment.

## 3. Check

- **Deployment-wide rules** run once: versions, FCV, health, sharding state, drivers.
- **Step rules** run for every upgrade step and come in two kinds:
  - **Catalog rules:** UCFM embeds a catalog per release, generated from the server source code of the newest release of each series: startup options, server parameters, commands, privilege actions and aggregation operators. Anything the deployment uses that exists in the step's source release but not in its target is reported at that step.
  - **Documented-change rules:** These cover compatibility changes from the MongoDB and Percona release notes that are not visible in the source code, such as THP for 8.0, unsupported kernels, and Queryable Encryption changes. Each one links to its documentation page.
- **Behavior-change rules.** Each documented behavior change is checked against evidence from the deployment:
  - server counters (`operatorCounters`, `aggStageCounters`, command counters, mongos hedging metrics) since each server started
  - server state (settings, indexes, collections, connections)
  - the profiler, when enabled
  - a document sample with `--deep-check`

  Without enough evidence, a check reports what to enable.
- **Audit rules** run only with `ucfm audit` or `--with-audit`.

Every check reports one of: `No issues found`, findings (`Error`, `Warning`, `Notice`), `Not applicable` (for example sharding checks on a replica set), or what it needs to run.

Catalogs exist for MongoDB Community 6.0, 7.0, 8.0, 8.3 and 9.0, and for Percona Server for MongoDB 6.0, 7.0, 8.0 and 8.3. Enterprise deployments use the Community catalogs.
