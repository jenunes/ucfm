# Commands and options

Every UCFM command, its options and its exit codes.

```text
ucfm check      --target VERSION  (--uri URI | --uri-file FILE | --from-snapshot FILE)  [options]
ucfm audit                        (--uri URI | --uri-file FILE | --from-snapshot FILE)  [options]
ucfm collect    --uri URI -o FILE                                     [options]
ucfm list-rules [--format text|md]
ucfm version
```

## Connecting

`--uri` takes a standard MongoDB connection string. Point it at one node. UCFM discovers the rest and connects to each member with the same credentials and TLS options.

| Deployment | Point `--uri` at | Example |
|---|---|---|
| Replica set | Any member | `mongodb://ucfm@db1:27017/?authSource=admin` |
| Sharded cluster | A mongos | `mongodb://ucfm@mongos1:27017/?authSource=admin` |
| Standalone | The server | `mongodb://ucfm@db1:27017/?authSource=admin` |
| With TLS | Any of the above | `mongodb://ucfm@db1:27017/?authSource=admin&tls=true&tlsCAFile=/etc/ssl/ca.pem` |

### Keeping the password off the command line

A password in `--uri` shows up in `ps` and in your shell history. Use one of these instead:

| Way | How |
|---|---|
| Leave it out | `--uri "mongodb://ucfm@db1:27017/?authSource=admin"`: UCFM asks for the password on the terminal, without echo |
| Environment variable | `export UCFM_URI="mongodb://ucfm:PASS@db1:27017/?authSource=admin"`, then run UCFM without `--uri` |
| File | `--uri-file ~/.ucfm-uri`: the first line that is not empty or a `#` comment. UCFM warns when other users can read the file (`chmod 600` it) |

`--uri` wins over `--uri-file`, which wins over `UCFM_URI`. x.509, Kerberos, AWS and OIDC connection strings never ask for a password.

The host running UCFM must reach every member by the host names stored in the replica set configuration. If it can't, add `--entry-only` to check only the node in `--uri`.

## Commands

| Command | Description |
|---|---|
| `check` | Check upgrade readiness for a target version and report action items |
| `audit` | Audit the deployment against the MongoDB Production Notes and Operations Checklist |
| `collect` | Collect a read-only snapshot of a deployment for offline analysis |
| `list-rules` | List the checks UCFM runs |
| `version` | Print the UCFM version |

## Connection and collection options

Used by `check`, `audit` and `collect`.

| Option | Description |
|---|---|
| `--uri URI` | Connection string of a mongod or mongos. Credentials and TLS options are reused for every member. Without a password, UCFM asks for it |
| `--uri-file FILE` | Read the connection string from FILE instead of `--uri` |
| `--entry-only` | Inspect only the node in `--uri` (connects to it directly); do not connect to other members, shards or routers |
| `--skip-data` | Do not list databases, collections, views and indexes |
| `--skip-security` | Do not read users and roles |
| `--max-namespaces N` | Stop listing collections after N namespaces (default 20000) |
| `--local` | Also read host settings; run on the database host (Linux) |
| `--config FILE` | mongod.conf to inspect (implies `--local`) |
| `--deep-check` | Sample up to 1000 documents per collection to verify changes that depend on stored data (reads documents) |
| `-v`, `--verbose` | Log collection progress to stderr |

## Analysis options

Used by `check` and `audit`.

| Option | Commands | Description |
|---|---|---|
| `--target VERSION` | check | Target version: `6.0`, `7.0`, `8.0`, `8.3` or `9.0` |
| `--from-snapshot FILE` | check, audit | Analyze a snapshot written by `collect` instead of connecting |
| `--save-snapshot FILE` | check, audit | Also write the collected snapshot to FILE |
| `--format text\|json\|md` | check, audit | Report format (default `text`) |
| `-o`, `--output FILE` | check, audit | Write the report to FILE instead of stdout |
| `--with-audit` | check | Append the production audit; does not change the exit code |
| `--issues-only` | check, audit | List only checks that found issues or could not run |

`collect` writes its snapshot with `-o`, `--output FILE`. `list-rules` accepts `--format text|md`.

`--uri` and `--from-snapshot` cannot be combined.

## Exit codes

| Code | `check` | `audit` |
|---|---|---|
| 0 | No warnings or errors | Notices only |
| 1 | Warnings, no errors | Warnings |
| 2 | Errors found: correct them before upgrading | — |
| 3 | UCFM failed (connection, options, unreadable snapshot) | Same |

Text output is colored on a terminal. Set `NO_COLOR=1` to disable colors.
