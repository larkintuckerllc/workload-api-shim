# SPIFFE Workload API Shim

## Go Environment Setup

This project uses Go `1.26.0`. The required version is specified in the `.go-version` file at the root of the repository.

### Prerequisites

Install [goenv](https://github.com/go-nv/goenv) to manage Go versions.

```bash
brew install goenv
```

Add the following to your `~/.zshrc`:

```zsh
export GOENV_ROOT="$HOME/.goenv"
export PATH="$GOENV_ROOT/bin:$PATH"
eval "$(goenv init -)"
```

Reload your shell:

```bash
source ~/.zshrc
```

### Install the required Go version

```bash
goenv install 1.26.0
```

### Verify

From the project root, confirm the correct version is active:

```bash
go version
# go version go1.26.0 darwin/arm64
```

goenv will automatically activate the correct version when you `cd` into this directory, based on the `.go-version` file.

## Running the Shim

### Build

```bash
go build ./cmd/workload-api-shim
```

### Usage

```
./workload-api-shim [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--socket-path` | `/tmp/spiffe-workload-api.sock` | Unix domain socket path the gRPC server listens on |
| `--creds-dir` | `/var/run/secrets/workload-spiffe-credentials` | Directory containing the SPIFFE credential files |

### Credential Files

The following files must be present in `--creds-dir`:

| File | Contents |
|---|---|
| `certificates.pem` | X.509 SVID — PEM-encoded certificate chain, leaf first |
| `private_key.pem` | SVID private key — PEM-encoded (PKCS#8, EC, or RSA) |
| `ca_certificates.pem` | Local trust domain CA bundle — PEM-encoded |
| `trust_bundles.json` | SPIFFE bundle document for all trust domains |

### Example

```bash
# Run with defaults (reads from /var/run/secrets/workload-spiffe-credentials)
./workload-api-shim

# Run with custom paths
./workload-api-shim \
  --socket-path /run/spiffe/workload.sock \
  --creds-dir /etc/spiffe/creds
```

Or without building first:

```bash
go run ./cmd/workload-api-shim \
  --socket-path /tmp/test.sock \
  --creds-dir /var/run/secrets/workload-spiffe-credentials
```

### Supported RPCs

| RPC | Type | Behavior |
|---|---|---|
| `FetchX509SVID` | server-stream | Returns the X.509 SVID and holds the stream open |
| `FetchX509Bundles` | server-stream | Returns local and federated X.509 trust bundles and holds the stream open |
| `FetchJWTBundles` | server-stream | Returns JWT trust bundles (empty when no `jwt-svid` keys are present) and holds the stream open |
| `FetchJWTSVID` | unary | Returns `Unimplemented` — no JWT signing keys in credential files |
| `ValidateJWTSVID` | unary | Returns `Unimplemented` — no JWT signing keys in credential files |

All RPCs require the `workload.spiffe.io: true` gRPC metadata header (per the SPIFFE Workload Endpoint spec). Calls without this header are rejected with `InvalidArgument`.

### Testing with grpcurl

```bash
# Missing header → InvalidArgument
grpcurl -plaintext -unix /tmp/test.sock \
  spiffe.workload.SpiffeWorkloadAPI/FetchX509SVID

# With required header → streams SVID response
grpcurl -plaintext -unix /tmp/test.sock \
  -H 'workload.spiffe.io: true' \
  spiffe.workload.SpiffeWorkloadAPI/FetchX509SVID
```
