#!/usr/bin/env bash
# Install or upgrade ucfm (Upgrade Checker For MongoDB).
#
#   curl -fsSL https://raw.githubusercontent.com/jenunes/ucfm/main/install.sh | bash
#
# Options (flags after "bash -s --", or environment variables):
#   --dir DIR          UCFM_INSTALL_DIR  where to put the binary
#                                        (default: /usr/local/bin as root, else ~/.local/bin)
#   UCFM_BASE_URL                        download from a mirror instead of GitHub
#                                        (expects <base>/<version>/<archive> and SHA256SUMS)
#
# It always installs the latest release; run it again to upgrade.
# Example: curl -fsSL .../install.sh | bash -s -- --dir /opt/ucfm/bin
set -euo pipefail

REPO="jenunes/ucfm"
VERSION=""
DIR="${UCFM_INSTALL_DIR:-}"
BASE_URL="${UCFM_BASE_URL:-}"

usage() {
	cat <<'USAGE'
Install or upgrade ucfm (Upgrade Checker For MongoDB).

  curl -fsSL https://raw.githubusercontent.com/jenunes/ucfm/main/install.sh | bash
  curl -fsSL .../install.sh | bash -s -- --dir /opt/ucfm/bin

It always installs the latest release; run it again to upgrade.

Options (or environment variables):
  --dir DIR          UCFM_INSTALL_DIR  install directory
                                       (default: /usr/local/bin as root, else ~/.local/bin)
                     UCFM_BASE_URL     download from a mirror instead of GitHub
USAGE
}

say()  { printf 'ucfm-install: %s\n' "$*" >&2; }
fail() { say "error: $*"; exit 1; }

while [ $# -gt 0 ]; do
	case "$1" in
	--dir) DIR="${2:-}"; shift 2 ;;
	--dir=*) DIR="${1#*=}"; shift ;;
	-h|--help) usage; exit 0 ;;
	*) fail "unknown option: $1" ;;
	esac
done

# --- platform -----------------------------------------------------------------
[ "$(uname -s)" = "Linux" ] || fail "ucfm binaries are built for Linux; this is $(uname -s)"
case "$(uname -m)" in
x86_64|amd64) ARCH=amd64 ;;
aarch64|arm64) ARCH=arm64 ;;
*) fail "unsupported architecture $(uname -m) (supported: x86_64, aarch64)" ;;
esac

# --- tools ----------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
	fetch() { # url dest [accept]
		curl -fsSL -H "Accept: ${3:-application/octet-stream}" -o "$2" "$1"
	}
elif command -v wget >/dev/null 2>&1; then
	fetch() {
		wget -q --header="Accept: ${3:-application/octet-stream}" -O "$2" "$1"
	}
else
	fail "curl or wget is required"
fi
command -v tar >/dev/null 2>&1 || fail "tar is required"
if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	fail "sha256sum or shasum is required"
fi

TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT

# --- latest release ---------------------------------------------------------------
if [ -n "$BASE_URL" ]; then
	fetch "$BASE_URL/latest" "$TMP/latest" text/plain || fail "cannot read $BASE_URL/latest"
	VERSION="$(tr -d '[:space:]' <"$TMP/latest")"
else
	fetch "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json" application/vnd.github+json ||
		fail "cannot find the latest release of $REPO"
	VERSION="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$TMP/latest.json" | head -n1)"
fi
[ -n "$VERSION" ] || fail "could not determine the latest release"
case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac

ARCHIVE="ucfm-$VERSION-linux-$ARCH.tar.gz"

# --- download -----------------------------------------------------------------------
download() { # name dest
	if [ -n "$BASE_URL" ]; then
		fetch "$BASE_URL/$VERSION/$1" "$2"
		return
	fi
	fetch "https://github.com/$REPO/releases/download/$VERSION/$1" "$2"
}

say "installing the latest release, ucfm $VERSION (linux/$ARCH)"
download "$ARCHIVE" "$TMP/$ARCHIVE" || fail "cannot download $ARCHIVE for $VERSION"
download SHA256SUMS "$TMP/SHA256SUMS" || fail "cannot download SHA256SUMS for $VERSION"

want="$(awk -v f="$ARCHIVE" '$2 == f {print $1}' "$TMP/SHA256SUMS")"
[ -n "$want" ] || fail "$ARCHIVE is not listed in SHA256SUMS"
got="$(sha256 "$TMP/$ARCHIVE")"
[ "$want" = "$got" ] || fail "checksum mismatch for $ARCHIVE (expected $want, got $got)"

tar -xzf "$TMP/$ARCHIVE" -C "$TMP"
BIN="$TMP/ucfm-$VERSION-linux-$ARCH/ucfm"
[ -f "$BIN" ] || fail "the archive does not contain ucfm"

# --- install --------------------------------------------------------------------------
if [ -z "$DIR" ]; then
	if [ "$(id -u)" -eq 0 ]; then DIR=/usr/local/bin; else DIR="$HOME/.local/bin"; fi
fi
mkdir -p "$DIR" || fail "cannot create $DIR"
[ -w "$DIR" ] || fail "$DIR is not writable (run as root, or pass --dir)"
previous=""
if [ -x "$DIR/ucfm" ]; then previous="$("$DIR/ucfm" version 2>/dev/null || true)"; fi
install -m 0755 "$BIN" "$DIR/ucfm.new"
mv -f "$DIR/ucfm.new" "$DIR/ucfm"

if [ -n "$previous" ]; then say "replaced: $previous"; fi
say "installed: $("$DIR/ucfm" version)"
say "location:  $DIR/ucfm"
case ":$PATH:" in
*":$DIR:"*) ;;
*) say "add $DIR to your PATH, for example: echo 'export PATH=\"\$PATH:$DIR\"' >> ~/.bashrc" ;;
esac
