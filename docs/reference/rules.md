# Rules

Every check UCFM runs. **Scope** shows when a rule runs:

- `deployment`: once per check
- a version step such as `7.0→8.0`: only for that step
- `every hop`: on every step
- `audit`: only in `ucfm audit` or `check --with-audit`

**Max severity** is the highest severity the rule can report.

Generated with `ucfm list-rules --format md`.

<!-- rules:begin -->
| Rule | Scope | Max severity | Category | Title |
|---|---|---|---|---|
| `binary-versions-consistent` | deployment | ERROR | path | Server versions across members |
| `fcv-matches-binary` | deployment | ERROR | path | featureCompatibilityVersion |
| `shard-access` | deployment | WARNING | path | Access to every shard |
| `replset-arbiters` | deployment | WARNING | topology | Arbiters (PSA architecture) |
| `replset-has-primary` | deployment | ERROR | topology | Replica set primary |
| `replset-members-healthy` | deployment | WARNING | topology | Replica set member health and replication lag |
| `sharding-balancer` | deployment | WARNING | topology | Balancer state |
| `sharding-no-migrations` | deployment | WARNING | topology | Chunk migrations and draining shards |
| `sharding-no-resharding` | deployment | ERROR | topology | Resharding operations in progress |
| `driver-compatibility` | deployment | NOTICE | platform | Connected driver versions |
| `backup-before-upgrade` | deployment | NOTICE | procedure | Backup before upgrading |
| `collection-gaps` | deployment | WARNING | procedure | Facts that could not be collected |
| `host-checks-coverage` | deployment | NOTICE | procedure | Host checks coverage |
| `startup-warnings` | deployment | NOTICE | procedure | Server startup warnings |
| `kernel-tcmalloc-compat` | 7.0→8.0,8.0→8.3,8.0→9.0,8.3→9.0 | ERROR | platform | Linux kernel compatibility with the 8.0 TCMalloc |
| `platform-os-supported` | every hop | WARNING | platform | Supported operating system for the target release |
| `config-option-deprecated` | every hop | WARNING | config | Deprecated or renamed startup options |
| `config-option-removed` | every hop | ERROR | config | Removed startup options |
| `free-monitoring-decommissioned` | 6.0→7.0 | NOTICE | config | Free monitoring settings |
| `initial-sync-filecopy-known-issue` | 8.0→8.3 | WARNING | config | File copy based initial sync |
| `psmdb-journal-option-ignored` | 6.0→7.0 | NOTICE | config | PSMDB journal options |
| `fle-substring-limits-override` | 8.0→9.0,8.3→9.0 | WARNING | parameters | fleDisableSubstringPreviewParameterLimits parameter |
| `parameter-deprecated` | 6.0→7.0,7.0→8.0 | NOTICE | parameters | Usage of deprecated server parameters |
| `parameter-removed` | every hop | ERROR | parameters | Removed server parameters |
| `parameter-renamed` | every hop | WARNING | parameters | Renamed server parameters |
| `command-deprecated-in-use` | 7.0→8.0,8.0→8.3,8.0→9.0 | NOTICE | commands | Usage of deprecated commands |
| `command-removed-in-use` | every hop | WARNING | commands | Usage of removed commands |
| `agg-operator-removed` | every hop | ERROR | data | Removed aggregation operators in views and validators |
| `group-empty-field-name` | 8.0→9.0,8.3→9.0 | ERROR | data | $group accumulators with an empty field name |
| `qe-preview-6x` | 6.0→7.0 | WARNING | data | Queryable Encryption 6.x preview collections |
| `qe-range-preview-removed` | 7.0→8.0 | ERROR | data | Queryable Encryption rangePreview fields |
| `qe-text-preview-removed` | 8.0→9.0,8.3→9.0 | ERROR | data | Queryable Encryption prefix/suffix/substring preview fields |
| `server-side-js-9.0` | 8.0→9.0,8.3→9.0 | WARNING | data | Usage of server-side JavaScript |
| `timeseries-timefield-dollar` | 8.0→8.3,8.0→9.0 | WARNING | data | Time series timeField names starting with $ |
| `views-on-system-buckets` | 6.0→7.0 | ERROR | data | Views on system.buckets namespaces |
| `ldap-deprecated` | 7.0→8.0 | NOTICE | security | LDAP authentication and authorization |
| `psmdb-kmip-key-active` | 6.0→7.0,7.0→8.0 | WARNING | security | PSMDB KMIP master key state |
| `psmdb-vault-metadata-permission` | 6.0→7.0,7.0→8.0 | WARNING | security | PSMDB Vault policy for secret metadata |
| `role-action-removed` | every hop | ERROR | security | Removed privilege actions in custom roles |
| `scram-sha1-with-fips` | 8.0→8.3,8.0→9.0 | ERROR | security | SCRAM-SHA-1 with FIPS mode |
| `2dsphere-error-codes` | 8.0→9.0,8.3→9.0 | NOTICE | behavior | 2dsphere key-extraction error codes |
| `2dsphere-index-v4` | 8.0→8.3,8.0→9.0 | NOTICE | behavior | 2dsphere index version 4 |
| `add-rounding` | 6.0→7.0 | WARNING | behavior | Floating-point rounding in $add |
| `addshard-maxsize` | 6.0→7.0 | WARNING | behavior | addShard maxSize setting |
| `autosplit-removed` | 6.0→7.0 | NOTICE | behavior | Automatic chunk splitting |
| `changestream-getmore-errors` | 8.0→9.0,8.3→9.0 | WARNING | behavior | Change stream getMore errors after elections |
| `chunksize-range` | 6.0→7.0 | ERROR | behavior | chunksize setting range |
| `compact-concurrency` | 7.0→8.0 | NOTICE | behavior | Concurrent compact operations |
| `dateadd-preepoch` | 8.0→8.3,8.0→9.0 | NOTICE | behavior | $dateAdd and $dateSubtract on pre-epoch dates |
| `ddl-via-mongos` | 8.0→8.3,8.0→9.0 | WARNING | behavior | DDL operations and applyOps on shard members |
| `direct-shard-operations` | 7.0→8.0 | WARNING | behavior | Commands run directly on shard members |
| `ftdc-directory-size` | 8.0→8.3,8.0→9.0 | NOTICE | behavior | FTDC directory size |
| `hedged-reads-default` | 7.0→8.0 | NOTICE | behavior | Hedged reads |
| `majority-write-ack` | 7.0→8.0 | NOTICE | behavior | Majority write concern acknowledgment |
| `multikey-query-killed` | 8.0→9.0,8.3→9.0 | NOTICE | behavior | Queries on fields that become multikey |
| `natural-hint-values` | 6.0→7.0 | WARNING | behavior | $natural hint and sort values |
| `null-undefined-match` | 7.0→8.0 | WARNING | behavior | Null equality matches on undefined values |
| `querystats-keys` | 8.0→9.0,8.3→9.0 | NOTICE | behavior | $queryStats keys for aggregate commands |
| `rename-cross-db-locks` | 8.0→9.0,8.3→9.0 | NOTICE | behavior | Cross-database renameCollection locking |
| `setclusterparameter-active` | 6.0→7.0 | WARNING | behavior | Active setClusterParameter operations |
| `system-buckets-orphans` | 7.0→8.0 | WARNING | behavior | system.buckets collections that are not time series |
| `timeseries-shardkey-timefield` | 7.0→8.0 | WARNING | behavior | Time series collections sharded on the timeField |
| `trim-limits` | 8.0→8.3,8.0→9.0 | NOTICE | behavior | $trim chars limit and text search memory |
| `tcmalloc-glibc-rseq` | 7.0→8.0,8.0→8.3,8.0→9.0,8.3→9.0 | NOTICE | host | glibc rseq and TCMalloc per-CPU caches |
| `thp-enabled-for-8.0` | 7.0→8.0,8.0→8.3,8.0→9.0,8.3→9.0 | WARNING | host | Transparent Huge Pages for MongoDB 8.0 and later |
| `prod-collection-gaps` | audit | WARNING | path | Facts that could not be collected |
| `prod-manual-checklist` | audit | NOTICE | path | Items that need a manual review |
| `prod-shard-access` | audit | WARNING | path | Access to every shard |
| `prod-members-identical` | audit | NOTICE | topology | Member hardware consistency |
| `prod-oplog-window` | audit | WARNING | topology | Oplog window |
| `prod-replset-hostnames` | audit | NOTICE | topology | Replica set member host names |
| `prod-replset-voting` | audit | WARNING | topology | Replica set voting members |
| `prod-cpu-cores` | audit | WARNING | platform | CPU cores |
| `prod-kernel-uek` | audit | WARNING | platform | Oracle Linux kernel (UEK or RHCK) |
| `prod-os-supported` | audit | WARNING | platform | Supported operating system for the running release |
| `prod-tcmalloc-per-cpu` | audit | WARNING | platform | TCMalloc per-CPU caches |
| `prod-connections` | audit | WARNING | config | Connection usage |
| `prod-journal` | audit | WARNING | config | Journaling |
| `prod-wt-cache` | audit | WARNING | config | WiredTiger cache size |
| `prod-authorization` | audit | WARNING | security | Access control |
| `prod-tls` | audit | NOTICE | security | Network encryption (TLS) |
| `prod-clock-sync` | audit | WARNING | host | Clock synchronization |
| `prod-disk-space` | audit | WARNING | host | Free space on the dbPath filesystem |
| `prod-filesystem` | audit | WARNING | host | dbPath filesystem type |
| `prod-io-scheduler` | audit | NOTICE | host | I/O scheduler |
| `prod-kernel-limits` | audit | NOTICE | host | Kernel limits |
| `prod-noatime` | audit | NOTICE | host | dbPath mount options |
| `prod-numa` | audit | WARNING | host | NUMA configuration |
| `prod-readahead` | audit | WARNING | host | Readahead of the dbPath device |
| `prod-selinux-js` | audit | NOTICE | host | SELinux and server-side JavaScript |
| `prod-swappiness` | audit | WARNING | host | Swappiness |
| `prod-tcp` | audit | NOTICE | host | TCP keepalive and retries |
| `prod-thp` | audit | WARNING | host | Transparent Huge Pages |
| `prod-ulimits` | audit | WARNING | host | Process limits (open files, processes) |
| `prod-host-coverage` | audit | NOTICE | procedure | Host checks coverage |
<!-- rules:end -->
