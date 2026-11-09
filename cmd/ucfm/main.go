// Command ucfm (Upgrade Checker For MongoDB) checks a MongoDB / Percona Server for MongoDB
// deployment for upgrade readiness: what would break if it were upgraded.
package main

import (
	"os"

	"github.com/jenunes/ucfm/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
