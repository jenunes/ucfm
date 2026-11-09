# Snapshots

A snapshot is a JSON file with everything UCFM collected. Collect it once, then run `check` or `audit` from it, anywhere and as often as you like.

Snapshots are useful when the database hosts have no internet access, to compare targets without reconnecting, or to review an upgrade with your team.

## Collect

```bash
ucfm collect --uri "mongodb://ucfm@db1:27017/?authSource=admin" -o snapshot.json
ucfm collect --uri "mongodb://ucfm@localhost:27017/?authSource=admin" --local -o db1.json   # with host facts
```

A live check can also keep its snapshot: `ucfm check ... --save-snapshot snapshot.json`.

## Analyze

```bash
ucfm check   --from-snapshot snapshot.json --target 8.0
ucfm check   --from-snapshot snapshot.json --target 9.0
ucfm audit   --from-snapshot snapshot.json
```

A check run from a snapshot gives the same findings as a live check.

## What a snapshot contains

| Included | Not included |
|---|---|
| Host names, versions, options and parameters | Passwords and credentials |
| Replica set and sharding state | Document data |
| Database, collection and index names, index definitions, view pipelines, validators | |
| User names, role definitions, connected driver versions | |
| Host facts (with `--local`) | |
| Server counters (operators, stages and commands used) | |
| Profiler evidence: counts and query shapes with literal values removed | Literal query values |
| With `--deep-check`: namespaces and field paths holding changed types, with counts | The sampled documents |

> [!WARNING]
> Review a snapshot before sharing it outside your organization. It describes your schema and topology.

## Next steps

- [Commands and options](../reference/commands.md)
