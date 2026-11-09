# UCFM documentation

UCFM _(Upgrade Checker For MongoDB)_ checks a MongoDB or Percona Server for MongoDB deployment before an upgrade. It reports compatibility issues to fix before upgrading and audits the deployment against MongoDB's production recommendations.

## Getting started

- [Requirements](getting-started/requirements.md): supported versions, network access and the database user
- [Installation](getting-started/installation.md)
- [Quick start](getting-started/quickstart.md): your first check in three steps

## Usage

- [Check upgrade readiness](usage/check.md)
- [Audit production settings](usage/audit.md)
- [Host checks](usage/host-checks.md): kernel, filesystem and limits (`--local`)
- [Snapshots](usage/snapshots.md): collect once, analyze later

## Reference

- [Commands and options](reference/commands.md)
- [Rules](reference/rules.md)
- [How it works](reference/how-it-works.md)
- [FAQ and troubleshooting](reference/faq.md)

## Project

- [Contributing](contributing.md)
- [Release notes](release-notes.md)
- [License](../LICENSE): Apache License 2.0
