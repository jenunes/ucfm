BINARY  := ucfm
PKG     := github.com/jenunes/ucfm
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X $(PKG)/internal/cli.Version=$(VERSION) -X $(PKG)/internal/cli.Commit=$(COMMIT)

GO ?= $(shell command -v go 2>/dev/null || echo $(HOME)/.local/go/bin/go)

.PHONY: all build dist test vet fmt lint linkcheck publiccheck catalogs docs clean

all: fmt vet test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/$(BINARY)

# Release archives: static Linux binaries for amd64 and arm64, plus checksums.
DIST_ARCHES := amd64 arm64
dist:
	rm -rf dist && mkdir -p dist
	@for arch in $(DIST_ARCHES); do \
		echo "building linux/$$arch"; \
		mkdir -p dist/$(BINARY)-$(VERSION)-linux-$$arch; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' \
			-o dist/$(BINARY)-$(VERSION)-linux-$$arch/$(BINARY) ./cmd/$(BINARY) || exit 1; \
		cp README.md LICENSE dist/$(BINARY)-$(VERSION)-linux-$$arch/; \
		tar -C dist -czf dist/$(BINARY)-$(VERSION)-linux-$$arch.tar.gz $(BINARY)-$(VERSION)-linux-$$arch; \
		rm -rf dist/$(BINARY)-$(VERSION)-linux-$$arch; \
	done
	cd dist && sha256sum *.tar.gz > SHA256SUMS
	@ls -l dist

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

# golangci-lint is optional locally (CI always runs it); skip gracefully when
# it is not installed.
lint: vet linkcheck publiccheck
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; \
	else echo "golangci-lint not installed; ran go vet, linkcheck and publiccheck only"; fi

# Relative links and #anchors in README.md and docs/ (no network).
linkcheck:
	$(GO) run ./tools/linkcheck README.md docs

# Nothing private in the tracked files: local-only paths, personal paths or
# e-mail addresses, real host names in snapshots. CI also checks every commit.
publiccheck:
	$(GO) run ./tools/publiccheck

# Regenerate the embedded per-version catalogs from upstream source tags.
catalogs:
	$(GO) run ./tools/catalog-gen -out internal/catalog/data

# Regenerate the rule table in docs/reference/rules.md from the registered rules.
docs: build
	@python3 -c 'import re,subprocess,sys; t=subprocess.run(["bin/$(BINARY)","list-rules","--format","md"],capture_output=True,text=True,check=True).stdout; r=open("docs/reference/rules.md").read(); r=re.sub(r"(<!-- rules:begin -->\n).*?(<!-- rules:end -->)", lambda m: m.group(1)+t+m.group(2), r, flags=re.S); open("docs/reference/rules.md","w").write(r)'
	@echo "docs/reference/rules.md updated"

clean:
	rm -rf bin/ dist/
