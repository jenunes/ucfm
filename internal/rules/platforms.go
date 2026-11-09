package rules

// Supported operating systems per release, limited to the Red Hat family
// (RHEL; Rocky Linux, AlmaLinux and Oracle Linux with RHCK are judged by
// their RHEL major version), Debian and Ubuntu, on x86_64 and arm64.
// Every list is copied from an official page; releases whose list could not
// be confirmed are absent, and rules report them as not checked.

// PlatformEntry is one supported OS version for a release.
type PlatformEntry struct {
	Family  string   // "rhel" | "debian" | "ubuntu"
	Version string   // RHEL/Debian major ("8", "9", "11", "12"); Ubuntu "20.04", "22.04", "24.04"
	Arches  []string // "x86_64", "arm64"
}

const (
	srcMongoPlatforms   = "https://www.mongodb.com/docs/community-platform-support/"
	srcMongoPlatforms60 = "https://web.archive.org/web/20250501130348/https://www.mongodb.com/docs/manual/administration/production-notes/"
	srcPerconaMongoOS   = "https://www.percona.com/release-lifecycle-percona-software-for-mongodb/"
)

var (
	both    = []string{"x86_64", "arm64"}
	x86only = []string{"x86_64"}
)

// supportedOS[flavor][release]; flavor "community" (also used for enterprise) or "psmdb".
var supportedOS = map[string]map[string][]PlatformEntry{
	"community": {
		// "Supported Platforms for MongoDB Community" (archived production notes,
		// 2025-05-01, table "Platform | Architecture | Edition | 8.0 | 7.0 | 6.0 | 5.0"),
		// 6.0 column, Community rows:
		//   Debian 11 | x86_64 | ✓            Debian 10 | x86_64 | ✓
		//   RHEL/Rocky/Alma/Oracle Linux 9.0+ | x86_64 | 6.0.4+
		//   RHEL/Rocky/Alma/Oracle Linux 8.0+ | x86_64 | ✓
		//   RHEL/Oracle Linux 7.0+ | x86_64 | ✓
		//   Ubuntu 22.04 | x86_64 | 6.0.4+     Ubuntu 20.04 | x86_64 | ✓   Ubuntu 18.04 | x86_64 | ✓
		//   RHEL/CentOS/Rocky/Alma 9 | arm64 | ✓   RHEL/CentOS/Rocky/Alma 8 | arm64 | ✓
		//   Ubuntu 22.04 | arm64 | 6.0.4+      Ubuntu 20.04 | arm64 | ✓    Ubuntu 18.04 | arm64 | ✓
		// The current page notes "v6.0 reached end of life on July 31, 2025".
		// "6.0.4+" rows are recorded as supported (minimum patch 6.0.4).
		"6.0": {
			{"rhel", "7", x86only},
			{"rhel", "8", both},
			{"rhel", "9", both},
			{"debian", "10", x86only},
			{"debian", "11", x86only},
			{"ubuntu", "18.04", both},
			{"ubuntu", "20.04", both},
			{"ubuntu", "22.04", both},
		},
		// "Supported Platforms for MongoDB Community", section "Linux",
		// table "Platform | Architecture | 9.x | 8.x | 7.x", 7.x column:
		//   Debian 12 | x86_64 | ✅   Debian 11 | x86_64 | ✅
		//   RHEL/Rocky/Alma/Oracle Linux 10 | x86_64 | ✅   RHEL/Rocky/Alma 10 | arm64 | ✅
		//   RHEL/Rocky/Alma/Oracle Linux 9.0+ | x86_64 | ✅  RHEL/Rocky/Alma 9 | arm64 | ✅
		//   RHEL/Rocky/Alma/Oracle Linux 8.0+ | x86_64 | ✅  RHEL/Rocky/Alma 8 | arm64 | ✅
		//   RHEL/Oracle Linux 7.0+ | x86_64 | ✅
		//   Ubuntu 22.04 | x86_64, arm64 | ✅   Ubuntu 20.04 | x86_64, arm64 | ✅
		// The Enterprise page has the same rows for these platforms.
		"7.0": {
			{"rhel", "7", x86only},
			{"rhel", "8", both},
			{"rhel", "9", both},
			{"rhel", "10", both},
			{"debian", "11", x86only},
			{"debian", "12", x86only},
			{"ubuntu", "20.04", both},
			{"ubuntu", "22.04", both},
		},
		// Same table, 8.x column (8.0 and 8.3 are 8.x releases):
		//   Debian 12 | x86_64 | ✅
		//   RHEL/Rocky/Alma/Oracle Linux 10, 9.0+, 8.0+ | x86_64 | ✅
		//   RHEL/Rocky/Alma 10, 9, 8 | arm64 | ✅
		//   Ubuntu 24.04, 22.04, 20.04 | x86_64, arm64 | ✅
		"8.0": {
			{"rhel", "8", both},
			{"rhel", "9", both},
			{"rhel", "10", both},
			{"debian", "12", x86only},
			{"ubuntu", "20.04", both},
			{"ubuntu", "22.04", both},
			{"ubuntu", "24.04", both},
		},
		"8.3": {
			{"rhel", "8", both},
			{"rhel", "9", both},
			{"rhel", "10", both},
			{"debian", "12", x86only},
			{"ubuntu", "20.04", both},
			{"ubuntu", "22.04", both},
			{"ubuntu", "24.04", both},
		},
		// Same table, 9.x column:
		//   Debian 12 | x86_64 | ✅   Debian 13 | x86_64 | ✅
		//   RHEL/Rocky/Alma/Oracle Linux 10, 9.0+, 8.0+ | x86_64 | ✅
		//   RHEL/Rocky/Alma 10, 9, 8 | arm64 | ✅
		//   Ubuntu 26.04 | x86_64, arm64 | 9.0.4+
		//   Ubuntu 24.04, 22.04 | x86_64, arm64 | ✅
		// "9.0.4+" is recorded as supported (minimum patch 9.0.4).
		"9.0": {
			{"rhel", "8", both},
			{"rhel", "9", both},
			{"rhel", "10", both},
			{"debian", "12", x86only},
			{"debian", "13", x86only},
			{"ubuntu", "22.04", both},
			{"ubuntu", "24.04", both},
			{"ubuntu", "26.04", both},
		},
	},
	"psmdb": {
		// Percona "Operating Systems support" table
		// ("Software → OS ↓ | OS EOL ↓ | PSMDB 7.x | PSMDB 8.x | PBM | PCSM"), PSMDB 7.x column:
		//   RHEL 8 | Active   RHEL 9 | Active   RHEL 10 | N/A
		//   Rocky Linux 8, 9 | Active   Oracle Linux 8, 9 | Active
		//   Ubuntu 22.04 LTS | Active   Ubuntu 24.04 LTS | Active
		//   Debian 11 | Inactive ("no longer supported since PSMDB 7.0.43-23")
		//   Debian 12 | Active
		// Footnote 3 (Debian rows): "Debian 11 and Debian 12 are not available for
		// ARM64 (AARCH64) architecture." ARM64 itself is supported per the PSMDB
		// 7.0 system requirements ("Support for ARM64 (AARch64) includes AWS
		// Graviton2 or newer processors").
		"7.0": {
			{"rhel", "8", both},
			{"rhel", "9", both},
			{"debian", "12", x86only},
			{"ubuntu", "22.04", both},
			{"ubuntu", "24.04", both},
		},
		// Same table, PSMDB 8.x column (8.0 and 8.3 are 8.x releases; the
		// Software Lifecycle Matrix lists PSMDB 8.3 GA 27-Oct-2026):
		//   RHEL 8, 9, 10 | Active   Rocky Linux 8, 9, 10 | Active   AlmaLinux 10 | Active
		//   Oracle Linux 8, 9, 10 | Active
		//   Ubuntu 22.04 LTS, 24.04 LTS | Active
		//   Debian 12 | Active   Debian 13 | Active   (Debian 11 | N/A)
		// Debian 13 carries footnote 3 like Debian 11 and 12; it is recorded as
		// x86_64 only because ARM64 availability is not stated for it.
		"8.0": {
			{"rhel", "8", both},
			{"rhel", "9", both},
			{"rhel", "10", both},
			{"debian", "12", x86only},
			{"debian", "13", x86only},
			{"ubuntu", "22.04", both},
			{"ubuntu", "24.04", both},
		},
		"8.3": {
			{"rhel", "8", both},
			{"rhel", "9", both},
			{"rhel", "10", both},
			{"debian", "12", x86only},
			{"debian", "13", x86only},
			{"ubuntu", "22.04", both},
			{"ubuntu", "24.04", both},
		},
		// PSMDB 6.0 is absent: it reached end of life on 31-Jul-2025 and its OS
		// list is no longer published by Percona.
	},
}

// supportedOSSources[flavor][release] = URL of the page the list comes from.
var supportedOSSources = map[string]map[string]string{
	"community": {
		"6.0": srcMongoPlatforms60,
		"7.0": srcMongoPlatforms,
		"8.0": srcMongoPlatforms,
		"8.3": srcMongoPlatforms,
		"9.0": srcMongoPlatforms,
	},
	"psmdb": {
		"7.0": srcPerconaMongoOS,
		"8.0": srcPerconaMongoOS,
		"8.3": srcPerconaMongoOS,
	},
}
