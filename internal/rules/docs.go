package rules

import (
	"fmt"
	"strings"
)

// Documentation links. LTS releases (x.0) have dedicated compatibility and
// upgrade pages; rapid releases are documented on their release-notes page.
const docsBase = "https://www.mongodb.com/docs/manual/release-notes/"

func isLTS(v string) bool { return strings.HasSuffix(v, ".0") }

// compatDoc is the "Compatibility Changes in MongoDB <v>" page. LTS and
// recent rapid releases (8.3) both have one.
func compatDoc(v string) string {
	return fmt.Sprintf("%s%s-compatibility/", docsBase, v)
}

// UpgradeDoc is the official upgrade procedure page for release v and a
// topology kind (standalone, replicaset, sharded).
func UpgradeDoc(v, kind string) string {
	if !isLTS(v) {
		// Rapid releases have one upgrade page from the previous LTS,
		// e.g. 8.3-upgrade-from-8.0.
		major := strings.SplitN(v, ".", 2)[0]
		return fmt.Sprintf("%s%s-upgrade-from-%s.0/", docsBase, v, major)
	}
	switch kind {
	case "sharded":
		return fmt.Sprintf("%s%s-upgrade-sharded-cluster/", docsBase, v)
	case "standalone":
		return fmt.Sprintf("%s%s-upgrade-standalone/", docsBase, v)
	default:
		return fmt.Sprintf("%s%s-upgrade-replica-set/", docsBase, v)
	}
}

const (
	docSetFCV       = "https://www.mongodb.com/docs/manual/reference/command/setFeatureCompatibilityVersion/"
	docReplStatus   = "https://www.mongodb.com/docs/manual/reference/command/replSetGetStatus/"
	docBalancer     = "https://www.mongodb.com/docs/manual/tutorial/manage-sharded-cluster-balancer/"
	docArbiters     = "https://www.mongodb.com/docs/manual/core/replica-set-arbiter/"
	docDrivers      = "https://www.mongodb.com/docs/drivers/"
	docPBMCompat    = "https://docs.percona.com/percona-backup-mongodb/"
	docProdNotes    = "https://www.mongodb.com/docs/manual/administration/production-notes/"
	docResharding   = "https://www.mongodb.com/docs/manual/core/sharding-reshard-a-collection/"
	docCustomRoles  = "https://www.mongodb.com/docs/manual/core/security-user-defined-roles/"
	docAggPipeline  = "https://www.mongodb.com/docs/manual/reference/operator/aggregation-pipeline/"
	docServerParams = "https://www.mongodb.com/docs/manual/reference/parameters/"
	docConfigOpts   = "https://www.mongodb.com/docs/manual/reference/configuration-options/"
)
