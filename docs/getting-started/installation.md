# Installation

UCFM is a single static Linux binary. Database servers don't need Go or any other dependency to run it.

| Method | Use it when |
|---|---|
| [One-line install](#one-line-install) | The usual choice: one command downloads, verifies and installs the latest release |
| [Download a release](#download-a-release) | The server has no internet access: download on another machine and copy |
| [Build and copy](#build-and-copy) | No release is published yet, or you want to build it yourself |
| [go install](#go-install) | The machine already has Go 1.27+ |

## One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/jenunes/ucfm/main/install.sh | bash
```

The script:
1. detects the architecture (`amd64` or `arm64`)
2. looks up the latest release and downloads it with its `SHA256SUMS`
3. verifies the checksum
4. installs `ucfm` into `/usr/local/bin` when run as root, otherwise into `~/.local/bin`

It always installs the latest release, so running it again upgrades. It needs `curl` or `wget`, `tar` and `sha256sum`.

| Option | Environment variable | Description |
|---|---|---|
| `--dir DIR` | `UCFM_INSTALL_DIR` | Install directory |
| | `UCFM_BASE_URL` | Download from an internal mirror (`<base>/latest`, `<base>/<version>/<archive>` and `SHA256SUMS`) |

```bash
curl -fsSL https://raw.githubusercontent.com/jenunes/ucfm/main/install.sh | bash -s -- --dir /opt/ucfm/bin
```

To uninstall, delete the binary: `rm "$(command -v ucfm)"`.

## Download a release

1. On a machine with internet access, download the archive for your architecture from the [Releases page](https://github.com/jenunes/ucfm/releases), together with `SHA256SUMS`. With the GitHub CLI:

   ```bash
   gh release download v1.0.0 --repo jenunes/ucfm --pattern 'ucfm-*-linux-amd64.tar.gz' --pattern SHA256SUMS
   ```

   Use `linux-arm64` instead of `linux-amd64` on ARM servers (`uname -m` prints `aarch64`).

2. Copy the files to the database server, then verify and install:

   ```bash
   scp ucfm-v1.0.0-linux-amd64.tar.gz SHA256SUMS db1:
   ssh db1
   sha256sum --ignore-missing -c SHA256SUMS
   tar -xzf ucfm-v1.0.0-linux-amd64.tar.gz
   sudo install -m 0755 ucfm-v1.0.0-linux-amd64/ucfm /usr/local/bin/ucfm
   ucfm version
   ```

> [!NOTE]
> The database server itself never needs internet access.

## Build and copy

On any machine with Go 1.27+, build the release archives and copy one to each server as above:

```bash
git clone https://github.com/jenunes/ucfm.git
cd ucfm
make dist          # dist/ucfm-<version>-linux-amd64.tar.gz, -linux-arm64.tar.gz and SHA256SUMS
```

For a single local binary, `make build` writes `bin/ucfm`.

## go install

On a machine that already has Go 1.27 or later:

```bash
go install github.com/jenunes/ucfm/cmd/ucfm@latest
export PATH="$PATH:$(go env GOPATH)/bin"      # where go install puts the binary
ucfm version
```

To keep the `PATH` change, add that line to your shell profile.

## Next steps

- [Quick start](quickstart.md)
