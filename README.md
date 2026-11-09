<p align="center"><img src="docs/assets/logo.jpg" alt="UCFM logo" width="320"></p>

# UCFM _(Upgrade Checker For MongoDB)_

UCFM checks whether a MongoDB or Percona Server for MongoDB deployment is ready to upgrade. It lists what would break and what to fix first.

- It runs only read commands and never changes the deployment.
- It supports MongoDB Community, Enterprise and Percona Server for MongoDB 6.0, 7.0, 8.0, 8.3 and 9.0, on standalone servers, replica sets and sharded clusters.
- Besides the action items for the next upgrade step, it audits production settings.
- It is a single static Linux binary, with nothing to install on the database hosts.

## Quick start

Install or upgrade with one command (Linux, no Go needed; see [Installation](docs/getting-started/installation.md) for other methods):

```bash
curl -fsSL https://raw.githubusercontent.com/jenunes/ucfm/main/install.sh | bash

ucfm check   --uri "mongodb://ucfm@db1:27017/?authSource=admin" --target 8.0
ucfm audit   --uri "mongodb://ucfm@db1:27017/?authSource=admin"
```

Example output (shortened):

```text
The MongoDB deployment at db1:27017 (replica set rs0, 3 members), Percona
Server for MongoDB 6.0.29-23, will now be checked for compatibility issues for
upgrade to MongoDB 7.0 (path 6.0 → 7.0)...

================================================================================
Deployment-wide checks
================================================================================

1) Upgrade path (upgrade-path)
   No issues found: from 6.0 (current) to 7.0 (target) is a supported upgrade
      path.

3) featureCompatibilityVersion (fcv-matches-binary)
   Error: The featureCompatibilityVersion is lower than the running binaries.
      The next binary upgrade will refuse to start until FCV equals the current
      release.

   - db1:27017: binary 6.0, FCV 5.0

   Solution:
   - After confirming you will not need to downgrade, run on the primary (or
      through mongos):
        db.adminCommand({setFeatureCompatibilityVersion: "6.0"})

   More information:
     https://www.mongodb.com/docs/manual/reference/command/setFeatureCompatibilityVersion/

8) Balancer state (sharding-balancer)
   Not applicable: not a sharded cluster.

================================================================================
Upgrade 6.0 → 7.0
Checked against Percona Server for MongoDB 7.0, psmdb-7.0.45-24
================================================================================

22) Removed server parameters (parameter-removed)
   Error: These server parameters are set at startup but do not exist in 7.0.
      The server fails to start with an unknown setParameter.

   - internalQueryForceClassicEngine [db2:27017]

   Solution:
   - Remove them from setParameter in the configuration file / command line.

================================================================================
Errors:   2
Warnings: 1
Notices:  4

Checks with errors:
   - 3) featureCompatibilityVersion (fcv-matches-binary)
   - 22) Removed server parameters (parameter-removed)

Checks with warnings:
   - 24) Usage of removed commands (command-removed-in-use)

2 errors were found. Correct them before upgrading to avoid compatibility
issues.
```

## Documentation

| | |
|---|---|
| **Getting started** | [Requirements](docs/getting-started/requirements.md) · [Installation](docs/getting-started/installation.md) · [Quick start](docs/getting-started/quickstart.md) |
| **Usage** | [Check upgrade readiness](docs/usage/check.md) · [Audit production settings](docs/usage/audit.md) · [Host checks](docs/usage/host-checks.md) · [Snapshots](docs/usage/snapshots.md) |
| **Reference** | [Commands and options](docs/reference/commands.md) · [Rules](docs/reference/rules.md) · [How it works](docs/reference/how-it-works.md) · [FAQ and troubleshooting](docs/reference/faq.md) |
| **Project** | [Contributing](docs/contributing.md) · [Release notes](docs/release-notes.md) |

## License

UCFM is open source under the [Apache License 2.0](LICENSE).
