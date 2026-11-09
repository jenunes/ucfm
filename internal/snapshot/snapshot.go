// Package snapshot defines the read-only picture of a deployment that the
// collectors produce and the rules consume. A snapshot is plain JSON so it can
// be collected on a customer's side and analyzed elsewhere.
package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// SchemaVersion is bumped on incompatible changes to the snapshot layout.
const SchemaVersion = 1

// Topology kinds.
const (
	KindStandalone = "standalone"
	KindReplicaSet = "replicaset"
	KindSharded    = "sharded"
)

// Node roles.
const (
	RolePrimary    = "PRIMARY"
	RoleSecondary  = "SECONDARY"
	RoleArbiter    = "ARBITER"
	RoleStandalone = "STANDALONE"
	RoleMongos     = "MONGOS"
)

// Snapshot is everything the tool knows about one deployment.
type Snapshot struct {
	SchemaVersion int       `json:"schemaVersion"`
	CollectedAt   time.Time `json:"collectedAt"`
	ToolVersion   string    `json:"toolVersion"`
	EntryHost     string    `json:"entryHost"`

	Topology Topology       `json:"topology"`
	Nodes    []Node         `json:"nodes"`
	Sharding *ShardingInfo  `json:"sharding,omitempty"`
	Data     DataInfo       `json:"data"`
	Security SecurityInfo   `json:"security"`
	Clients  []ClientDriver `json:"clients,omitempty"`
	Host     *HostInfo      `json:"host,omitempty"`

	// Collection records how the snapshot was collected, so rules can tell
	// "not checked" apart from "no issues".
	Collection CollectionInfo `json:"collection"`

	// DefaultRWConcern is getDefaultRWConcern from the entry node.
	DefaultRWConcern *DefaultRWConcern `json:"defaultRWConcern,omitempty"`
	// ActiveSetClusterParameter counts setClusterParameter operations in
	// progress at collection time ($currentOp on the entry node).
	ActiveSetClusterParameter int `json:"activeSetClusterParameter,omitempty"`
	// Profiler holds redacted evidence from system.profile collections.
	Profiler *ProfilerInfo `json:"profiler,omitempty"`
	// DeepCheck holds the results of --deep-check document sampling.
	DeepCheck *DeepCheckInfo `json:"deepCheck,omitempty"`

	// Errors records what could not be collected (missing privileges,
	// unreachable members, ...). Rules use it to say "not checked".
	Errors []CollectError `json:"errors,omitempty"`
}

// CollectError is a non-fatal collection failure.
type CollectError struct {
	Scope   string `json:"scope"` // e.g. "node:host:27017", "data", "security"
	Command string `json:"command"`
	Message string `json:"message"`
}

// Topology describes the deployment layout.
type Topology struct {
	Kind     string    `json:"kind"`
	ReplSets []ReplSet `json:"replSets,omitempty"` // shards + config server, or the single RS
	Mongos   []Mongos  `json:"mongos,omitempty"`
}

// ReplSet is one replica set (a plain RS, a shard, or the config server).
type ReplSet struct {
	Name    string   `json:"name"`
	Role    string   `json:"role"` // "replset", "shard", "config"
	Members []Member `json:"members"`
}

// Member merges replSetGetStatus and replSetGetConfig for one member.
type Member struct {
	Host        string    `json:"host"`
	State       string    `json:"state"`
	Health      float64   `json:"health"`
	Priority    float64   `json:"priority"`
	Votes       int       `json:"votes"`
	ArbiterOnly bool      `json:"arbiterOnly,omitempty"`
	Hidden      bool      `json:"hidden,omitempty"`
	Delayed     bool      `json:"delayed,omitempty"`
	OptimeDate  time.Time `json:"optimeDate,omitempty"`
	LagSeconds  float64   `json:"lagSeconds"`
}

// Mongos is one router registered in config.mongos.
type Mongos struct {
	Host    string    `json:"host"`
	Version string    `json:"version"`
	Ping    time.Time `json:"ping"`
	Up      int64     `json:"up"`
}

// Node holds facts collected from one mongod/mongos process.
type Node struct {
	Host      string `json:"host"`
	Role      string `json:"role"`
	ReplSet   string `json:"replSet,omitempty"`
	ShardName string `json:"shardName,omitempty"`
	IsConfig  bool   `json:"isConfig,omitempty"`

	Version       string   `json:"version"`
	GitVersion    string   `json:"gitVersion,omitempty"`
	Flavor        string   `json:"flavor"` // community | enterprise | psmdb
	PSMDBVersion  string   `json:"psmdbVersion,omitempty"`
	Modules       []string `json:"modules,omitempty"`
	StorageEngine string   `json:"storageEngine,omitempty"`
	FCV           string   `json:"fcv,omitempty"`

	// Argv and Options come from getCmdLineOpts. Options are flattened to
	// dotted YAML paths ("net.bindIp"); setParameter entries are kept apart.
	Argv              []string                   `json:"argv,omitempty"`
	Options           map[string]json.RawMessage `json:"options,omitempty"`
	StartupParameters map[string]json.RawMessage `json:"startupParameters,omitempty"`
	ConfigFile        string                     `json:"configFile,omitempty"`

	// Parameters is getParameter:'*' (runtime values of every parameter).
	Parameters map[string]json.RawMessage `json:"parameters,omitempty"`

	// CommandCounters is serverStatus.metrics.commands.<name>.total.
	CommandCounters map[string]int64 `json:"commandCounters,omitempty"`
	// OpcountersDeprecated is serverStatus.opcountersDeprecated, if present.
	OpcountersDeprecated map[string]int64 `json:"opcountersDeprecated,omitempty"`
	UptimeSeconds        int64            `json:"uptimeSeconds,omitempty"`
	Connections          *Connections     `json:"connections,omitempty"`
	Oplog                *OplogInfo       `json:"oplog,omitempty"`
	// AggStageCounters is serverStatus metrics.aggStageCounters (stage -> uses).
	AggStageCounters map[string]int64 `json:"aggStageCounters,omitempty"`
	// OperatorCounters is serverStatus metrics.operatorCounters, by group
	// (expressions, match, groupAccumulators, windowAccumulators) -> operator -> uses.
	OperatorCounters map[string]map[string]int64 `json:"operatorCounters,omitempty"`
	// Hedging is serverStatus hedgingMetrics (mongos only).
	Hedging *HedgingMetrics `json:"hedging,omitempty"`
	// TCMalloc is serverStatus tcmalloc per-CPU cache state; only servers
	// running the 8.0+ TCMalloc report it.
	TCMalloc *TCMallocInfo `json:"tcmalloc,omitempty"`
	// Clients are application drivers connected to this node. Collected on
	// shard members of sharded clusters (direct, non-mongos connections).
	Clients []ClientDriver `json:"clients,omitempty"`

	StartupWarnings []string    `json:"startupWarnings,omitempty"`
	HostInfo        HostInfoCmd `json:"hostInfo"`
}

// HostInfoCmd is the subset of the hostInfo command the rules need.
type HostInfoCmd struct {
	Hostname      string `json:"hostname,omitempty"`
	CPUArch       string `json:"cpuArch,omitempty"`
	NumCores      int    `json:"numCores,omitempty"`
	MemSizeMB     int64  `json:"memSizeMB,omitempty"`
	NUMAEnabled   bool   `json:"numaEnabled,omitempty"`
	OSType        string `json:"osType,omitempty"`
	OSName        string `json:"osName,omitempty"`
	OSVersion     string `json:"osVersion,omitempty"`
	LibcVersion   string `json:"libcVersion,omitempty"`
	KernelVersion string `json:"kernelVersion,omitempty"`
	CPUFeatures   string `json:"cpuFeatures,omitempty"`
	// MemLimitMB is the memory available to mongod (cgroup limit aware).
	MemLimitMB int64 `json:"memLimitMB,omitempty"`
}

// OplogInfo describes a member's oplog (local.oplog.rs).
type OplogInfo struct {
	MaxSizeMB   int64     `json:"maxSizeMB"`
	UsedMB      int64     `json:"usedMB"`
	First       time.Time `json:"first"`
	Last        time.Time `json:"last"`
	WindowHours float64   `json:"windowHours"`
}

// Connections is serverStatus.connections.
type Connections struct {
	Current   int64 `json:"current"`
	Available int64 `json:"available"`
}

// ShardingInfo is cluster-level sharding state read through mongos.
type ShardingInfo struct {
	Shards             []Shard `json:"shards"`
	BalancerMode       string  `json:"balancerMode,omitempty"`
	BalancerRunning    bool    `json:"balancerRunning"`
	ActiveMigrations   int     `json:"activeMigrations"`
	ActiveResharding   int     `json:"activeResharding"`
	ShardedCollections int     `json:"shardedCollections"`
	// ChunkSizeMB is config.settings {_id: "chunksize"} (0 = not set, default).
	ChunkSizeMB int64 `json:"chunkSizeMB,omitempty"`
	// AutoSplit is config.settings {_id: "autosplit"}.enabled (nil = not set).
	AutoSplit *bool `json:"autoSplit,omitempty"`
	// Collections are the config.collections entries (shard keys), without
	// config.system.sessions. Not collected with --skip-data.
	Collections []ShardedCollection `json:"collections,omitempty"`
	// CollectionsRead is true when config.collections was read.
	CollectionsRead bool `json:"collectionsRead,omitempty"`
	// CollectionsTruncated is true when --max-namespaces cut the list.
	CollectionsTruncated bool `json:"collectionsTruncated,omitempty"`
}

// ShardedCollection is one config.collections entry.
type ShardedCollection struct {
	// NS is the namespace as stored, e.g. "db.system.buckets.ts" for a
	// time series collection.
	NS     string     `json:"ns"`
	Key    []IndexKey `json:"key"`
	Unique bool       `json:"unique,omitempty"`
	// Unsplittable marks 8.0+ collections tracked by the config server but
	// not sharded (key {_id: 1}, one chunk).
	Unsplittable bool `json:"unsplittable,omitempty"`
	// TimeField and MetaField come from timeseriesFields (time series only).
	TimeField string `json:"timeField,omitempty"`
	MetaField string `json:"metaField,omitempty"`
}

// Shard is one entry of listShards.
type Shard struct {
	ID       string `json:"id"`
	Host     string `json:"host"` // "rs/h1:27017,h2:27017"
	Draining bool   `json:"draining,omitempty"`
	// MaxSizeMB is the legacy addShard maxSize from config.shards (0 = unset).
	MaxSizeMB int64 `json:"maxSizeMB,omitempty"`
}

// DataInfo describes databases, collections, views and indexes.
type DataInfo struct {
	Databases []Database `json:"databases"`
	Truncated bool       `json:"truncated,omitempty"` // hit --max-namespaces
}

// Database is one database and its namespaces.
type Database struct {
	Name        string       `json:"name"`
	SizeOnDisk  int64        `json:"sizeOnDisk"`
	Collections []Collection `json:"collections"`
	// BucketCollections are the system.buckets.* namespaces (names only).
	BucketCollections []string `json:"bucketCollections,omitempty"`
}

// Collection is one namespace (collection, view or time-series).
type Collection struct {
	Name    string          `json:"name"`
	Type    string          `json:"type"` // collection | view | timeseries
	Options json.RawMessage `json:"options,omitempty"`
	// Convenience fields lifted from Options.
	ViewOn          string          `json:"viewOn,omitempty"`
	Pipeline        json.RawMessage `json:"pipeline,omitempty"`
	Validator       json.RawMessage `json:"validator,omitempty"`
	EncryptedFields json.RawMessage `json:"encryptedFields,omitempty"`
	Capped          bool            `json:"capped,omitempty"`
	Clustered       bool            `json:"clustered,omitempty"`
	Indexes         []Index         `json:"indexes,omitempty"`
	// Hidden is set for views found in system.views that listCollections does
	// not return (views on system.buckets.* namespaces).
	Hidden bool `json:"hidden,omitempty"`
}

// Index is one index spec from listIndexes.
type Index struct {
	Name string          `json:"name"`
	Key  []IndexKey      `json:"key"`
	Spec json.RawMessage `json:"spec"` // the full spec, relaxed extended JSON
}

// IndexKey is one ordered field of an index key pattern.
type IndexKey struct {
	Field string          `json:"field"`
	Value json.RawMessage `json:"value"` // 1, -1, "text", "2dsphere", "hashed", ...
}

// SecurityInfo holds users (no credentials) and user-defined roles.
type SecurityInfo struct {
	Users []User `json:"users,omitempty"`
	Roles []Role `json:"roles,omitempty"`
}

// User is one user from usersInfo (never credentials).
type User struct {
	User       string    `json:"user"`
	DB         string    `json:"db"`
	Mechanisms []string  `json:"mechanisms,omitempty"`
	Roles      []RoleRef `json:"roles,omitempty"`
}

// RoleRef names a role.
type RoleRef struct {
	Role string `json:"role"`
	DB   string `json:"db"`
}

// Role is one user-defined role with its direct privileges.
type Role struct {
	Role       string      `json:"role"`
	DB         string      `json:"db"`
	Privileges []Privilege `json:"privileges,omitempty"`
	Roles      []RoleRef   `json:"roles,omitempty"`
}

// Privilege is a resource plus action list.
type Privilege struct {
	Resource json.RawMessage `json:"resource"`
	Actions  []string        `json:"actions"`
}

// ClientDriver aggregates connected clients by driver and version.
type ClientDriver struct {
	DriverName    string   `json:"driverName"`
	DriverVersion string   `json:"driverVersion"`
	AppNames      []string `json:"appNames,omitempty"`
	Connections   int      `json:"connections"`
	SeenOn        []string `json:"seenOn,omitempty"`
}

// HostInfo holds facts gathered locally on the database host (--local).
type HostInfo struct {
	Hostname string `json:"hostname"`
	// Node is the deployment member this machine is ("host:port"), set when
	// the facts are collected; empty when the machine is not a member, in
	// which case rules must not use these facts.
	Node string `json:"node,omitempty"`
	// LocalAddrs are the IP addresses of this machine's interfaces.
	LocalAddrs    []string          `json:"localAddrs,omitempty"`
	OSRelease     map[string]string `json:"osRelease,omitempty"`
	KernelVersion string            `json:"kernelVersion,omitempty"`
	GlibcVersion  string            `json:"glibcVersion,omitempty"`
	GlibcTunables string            `json:"glibcTunables,omitempty"`
	THPEnabled    string            `json:"thpEnabled,omitempty"` // [always] madvise never
	THPDefrag     string            `json:"thpDefrag,omitempty"`
	// THPMaxPtesNone is /sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none.
	THPMaxPtesNone string `json:"thpMaxPtesNone,omitempty"`
	// MongodProcesses are the local mongod/mongos processes found in /proc,
	// with the environment and limits that matter for upgrades.
	MongodProcesses []LocalProcess             `json:"mongodProcesses,omitempty"`
	CPUFlags        []string                   `json:"cpuFlags,omitempty"`
	NUMANodes       int                        `json:"numaNodes,omitempty"`
	Ulimits         map[string]string          `json:"ulimits,omitempty"`
	ConfigFile      string                     `json:"configFile,omitempty"`
	ConfigOptions   map[string]json.RawMessage `json:"configOptions,omitempty"` // flattened mongod.conf
	DBPath          string                     `json:"dbPath,omitempty"`
	DBPathFS        string                     `json:"dbPathFS,omitempty"`
	DBPathFreeMB    int64                      `json:"dbPathFreeMB,omitempty"`
	DBPathUsedMB    int64                      `json:"dbPathUsedMB,omitempty"`
	// Production-notes facts (ucfm audit).
	Sysctls           map[string]string `json:"sysctls,omitempty"` // vm.swappiness -> "60"
	DBPathDevice      string            `json:"dbPathDevice,omitempty"`
	DBPathMountOpts   []string          `json:"dbPathMountOpts,omitempty"`
	ReadaheadKB       string            `json:"readaheadKB,omitempty"` // /sys/block/<dev>/queue/read_ahead_kb
	IOScheduler       string            `json:"ioScheduler,omitempty"` // raw, e.g. "[none] mq-deadline"
	NumadRunning      bool              `json:"numadRunning,omitempty"`
	ClockSynced       *bool             `json:"clockSynced,omitempty"` // nil = unknown
	SELinux           string            `json:"selinux,omitempty"`     // enforcing | permissive | disabled
	CgroupMemoryMaxMB int64             `json:"cgroupMemoryMaxMB,omitempty"`
	Errors            []CollectError    `json:"errors,omitempty"`
}

// CollectionInfo records the collection options used for a snapshot.
type CollectionInfo struct {
	EntryOnly    bool `json:"entryOnly,omitempty"`
	SkipData     bool `json:"skipData,omitempty"`
	SkipSecurity bool `json:"skipSecurity,omitempty"`
	DeepCheck    bool `json:"deepCheck,omitempty"`
	Local        bool `json:"local,omitempty"`
	// ConnTemplate is the connection string used, with the password replaced
	// by "****" and the host list replaced by "{host}", e.g.
	// "mongodb://dba:****@{host}/?authSource=admin". It lets reports print
	// ready-to-run commands for each host. It never contains a password.
	ConnTemplate string `json:"connTemplate,omitempty"`
}

// TCMallocInfo is the per-CPU cache state from serverStatus tcmalloc.
type TCMallocInfo struct {
	UsingPerCPUCaches       bool  `json:"usingPerCPUCaches"`
	MaxPerCPUCacheSizeBytes int64 `json:"maxPerCPUCacheSizeBytes,omitempty"`
	// CPUFreeBytes is tcmalloc.tcmalloc.cpu_free.
	CPUFreeBytes int64 `json:"cpuFreeBytes"`
}

// HedgingMetrics is serverStatus hedgingMetrics on mongos.
type HedgingMetrics struct {
	NumTotalOperations                int64 `json:"numTotalOperations"`
	NumTotalHedgedOperations          int64 `json:"numTotalHedgedOperations"`
	NumAdvantageouslyHedgedOperations int64 `json:"numAdvantageouslyHedgedOperations"`
}

// DefaultRWConcern is getDefaultRWConcern (relaxed extended JSON values).
type DefaultRWConcern struct {
	WriteConcern       json.RawMessage `json:"writeConcern,omitempty"`
	ReadConcern        json.RawMessage `json:"readConcern,omitempty"`
	WriteConcernSource string          `json:"writeConcernSource,omitempty"`
	ReadConcernSource  string          `json:"readConcernSource,omitempty"`
}

// ProfilerInfo is evidence found in system.profile. Examples are redacted
// query shapes: literal values are replaced by "?" except the value that is
// the evidence itself ($natural direction, null).
type ProfilerInfo struct {
	DatabasesProfiled []string                     `json:"databasesProfiled,omitempty"`
	EntriesScanned    int                          `json:"entriesScanned"`
	Evidence          map[string]*ProfilerEvidence `json:"evidence,omitempty"`
}

// ProfilerEvidence counts profiler entries matching one detector.
type ProfilerEvidence struct {
	Count    int      `json:"count"`
	Examples []string `json:"examples,omitempty"`
}

// Profiler detector keys.
const (
	EvidenceNatural  = "natural" // hint/sort $natural with a value other than 1/-1
	EvidenceNullEq   = "nullEq"  // equality to null in a query filter
	EvidenceOpPrefix = "op:"     // operator used, e.g. "op:$add"
)

// DeepCheckInfo is the result of --deep-check document sampling. Only
// namespaces, field paths and counts are kept, never document contents.
type DeepCheckInfo struct {
	Ran         bool             `json:"ran"`
	Collections int              `json:"collections"`
	Documents   int              `json:"documents"`
	Undefined   []UndefinedField `json:"undefined,omitempty"`
}

// UndefinedField is a field path holding the deprecated BSON undefined type.
type UndefinedField struct {
	NS    string `json:"ns"`
	Path  string `json:"path"` // dotted; array positions are "$"
	Count int    `json:"count"`
}

// LocalProcess is a mongod/mongos process running on the local host.
type LocalProcess struct {
	PID           int      `json:"pid"`
	Name          string   `json:"name"`
	Cmdline       []string `json:"cmdline,omitempty"`
	GlibcTunables string   `json:"glibcTunables,omitempty"`
	EnvReadable   bool     `json:"envReadable"`
	// NUMAInterleave is true when numa_maps shows an interleave policy
	// (mongod started under numactl --interleave=all); nil = unknown.
	NUMAInterleave *bool             `json:"numaInterleave,omitempty"`
	Limits         map[string]string `json:"limits,omitempty"` // "Max open files" -> "64000 64000"
}

// AddError records a non-fatal collection error.
func (s *Snapshot) AddError(scope, command string, err error) {
	s.Errors = append(s.Errors, CollectError{Scope: scope, Command: command, Message: err.Error()})
}

// DataNodes returns mongod nodes (not mongos, not arbiters).
func (s *Snapshot) DataNodes() []Node {
	var out []Node
	for _, n := range s.Nodes {
		if n.Role != RoleMongos && n.Role != RoleArbiter {
			out = append(out, n)
		}
	}
	return out
}

// SourceVersion returns the lowest major.minor binary version among nodes,
// which is the effective upgrade starting point.
func (s *Snapshot) SourceVersion() string {
	var versions []string
	for _, n := range s.Nodes {
		if mm := MajorMinor(n.Version); mm != "" {
			versions = append(versions, mm)
		}
	}
	if len(versions) == 0 {
		return ""
	}
	sort.Slice(versions, func(i, j int) bool { return CompareVersions(versions[i], versions[j]) < 0 })
	return versions[0]
}

// Flavor returns the deployment flavor (psmdb wins over enterprise/community
// if any node reports it).
func (s *Snapshot) Flavor() string {
	f := ""
	for _, n := range s.Nodes {
		switch n.Flavor {
		case "psmdb":
			return "psmdb"
		case "enterprise":
			f = "enterprise"
		case "community":
			if f == "" {
				f = "community"
			}
		}
	}
	return f
}

// Save writes the snapshot as indented JSON.
func (s *Snapshot) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Load reads a snapshot file and checks its schema version.
func Load(path string) (*Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse snapshot %s: %w", path, err)
	}
	if s.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("snapshot %s has schema version %d, this tool reads %d", path, s.SchemaVersion, SchemaVersion)
	}
	return &s, nil
}
