# Contributing

How to build, test and extend UCFM.

## Build and test

Requires Go 1.27 or later.

```bash
make build      # bin/ucfm
make test       # go test ./...
make lint       # go vet and linkcheck, plus golangci-lint when installed
make linkcheck  # relative links and #anchors in README.md and docs/
make publiccheck # nothing private in the tracked files
make docs       # regenerate docs/reference/rules.md from the registered rules
make dist       # release archives for linux/amd64 and linux/arm64 + SHA256SUMS
```

Every push and pull request runs the same checks in GitHub Actions (`.github/workflows/ci.yml`): publiccheck (including every commit's author e-mail, which must be a GitHub noreply address), gofmt, go vet, go test, a tidy `go.mod`, an up-to-date `docs/reference/rules.md`, linkcheck and golangci-lint.

## Project layout

| Path | Content |
|---|---|
| `cmd/ucfm` | Entry point |
| `internal/cli` | Commands and options |
| `internal/collect` | Read-only collection from the deployment |
| `internal/host` | Host settings (`--local`) |
| `internal/snapshot` | Snapshot format |
| `internal/upgradepath` | Upgrade path planning |
| `internal/catalog` | Embedded per-release catalogs |
| `internal/rules` | Rules and the rule engine |
| `internal/report` | Report output (text, JSON, Markdown) |
| `tools/catalog-gen` | Catalog generator |
| `tools/linkcheck` | Link and anchor checker for the docs |
| `tools/publiccheck` | Checks that nothing private is committed |
| `testdata/snapshots` | Snapshots from test deployments, used by tests |

## Adding a rule

1. Add the rule in `internal/rules`:
   - `global.go` for deployment-wide rules
   - `curated.go` for documented changes of an upgrade step
   - `production.go` for audit rules
2. Base it on official documentation. Set `DocURL` to the page and quote the key sentence in a comment.
3. Detect only what the snapshot shows; never guess. If a fact is missing, report nothing or add it to the collector.
4. Add positive and negative tests.
5. Run `make test docs`.

## Regenerating catalogs

Catalogs are generated from the upstream source tags (`mongodb/mongo` and `percona/percona-server-mongodb`):

```bash
make catalogs                                              # all series
go run ./tools/catalog-gen -report internal/catalog/data   # what changes between releases
```

## Test deployments

Rule tests run against the snapshots in `testdata/snapshots`. To add one:
1. Build a test deployment, for example with [anydbver](https://github.com/zelmario/anydbver) or MongoDB tarballs.
2. Create the condition you want to test, for example with `mongosh`.
3. Save a snapshot with `ucfm collect`.
4. Replace host names with neutral ones (`db1`, `db2`, `cfg1`, `mongos1`) before committing it; `make lint` rejects anything else.

## Publishing a release

Push a tag; `.github/workflows/release.yml` runs the tests, builds the archives with `make dist` and publishes the GitHub release with `docs/release-notes.md` as its notes:

```bash
git tag -a v1.0.0 -m "UCFM 1.0.0" && git push origin v1.0.0
```

When the release already exists, the job replaces its archives and notes. By hand, the same is:

```bash
make dist                                  # version comes from the tag
gh release create v1.0.0 dist/* --title "v1.0.0" --notes-file docs/release-notes.md
```

`install.sh` downloads `ucfm-<version>-linux-<arch>.tar.gz` and `SHA256SUMS` from the release, so keep the `make dist` file names. To test the installer without publishing, serve a mirror with `latest`, `<version>/<archive>` and `<version>/SHA256SUMS`, and run it with `UCFM_BASE_URL=http://host:port`.

### Versions

A published tag never moves. The Go module proxy and sum.golang.org keep every version they have seen, so a moved tag breaks `go install` with a checksum mismatch, and archives that people already downloaded no longer match. From then on, every change gets a new version, chosen by the maintainer.
