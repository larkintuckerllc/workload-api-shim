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

## Container

The image is built as a multi-arch manifest covering `linux/amd64` and `linux/arm64`. The build stage cross-compiles the Go binary for the target platform (no QEMU emulation), and the final image is based on `gcr.io/distroless/static-debian12:nonroot` — no shell, runs as non-root.

### Prerequisites

Enable [Docker BuildKit](https://docs.docker.com/build/buildkit/) and create a multi-platform builder if you haven't already:

```bash
docker buildx create --name multiarch --use
docker buildx inspect --bootstrap
```

### Build and push a multi-arch image

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag <registry>/<image>:<tag> \
  --push \
  .
```

### Build locally (single arch, load into Docker daemon)

```bash
docker buildx build \
  --platform linux/amd64 \
  --tag workload-api-shim:dev \
  --load \
  .
```

### Run the container

The shim needs:
- The credential directory bind-mounted to `--creds-dir`
- The socket directory bind-mounted so the host (or a sidecar) can reach the Unix socket

```bash
docker run --rm \
  -v /var/run/secrets/workload-spiffe-credentials:/var/run/secrets/workload-spiffe-credentials:ro \
  -v /run/spiffe:/run/spiffe \
  <registry>/<image>:<tag> \
  --socket-path /run/spiffe/workload.sock \
  --creds-dir /var/run/secrets/workload-spiffe-credentials
```

### Kubernetes (GKE Fleet sidecar pattern)

The shim is a long-running process and must run alongside the main container, not before it. Use the [native sidecar container](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) pattern available in Kubernetes 1.29+ by adding `restartPolicy: Always` to an `initContainers` entry. Kubernetes will start the sidecar before the main containers and keep it running for the lifetime of the pod.

On GKE, credentials are provisioned by the `podcertificate.gke.io` CSI driver. The socket is shared with the main container via an `emptyDir` volume.

```yaml
apiVersion: v1
kind: Pod
metadata:
  namespace: debug
  name: example
spec:
  initContainers:
  - name: workload-api-shim
    image: <registry>/<image>:<tag>
    args:
    - --socket-path=/run/spiffe/workload.sock
    - --creds-dir=/var/run/secrets/workload-spiffe-credentials
    restartPolicy: Always
    volumeMounts:
    - name: spiffe-socket
      mountPath: /run/spiffe
    - name: fleet-spiffe-credentials
      mountPath: /var/run/secrets/workload-spiffe-credentials
      readOnly: true
  containers:
  - name: main
    image: <your-workload-image>
    env:
    - name: SPIFFE_ENDPOINT_SOCKET
      value: unix:///run/spiffe/workload.sock
    volumeMounts:
    - name: spiffe-socket
      mountPath: /run/spiffe
  volumes:
  - name: spiffe-socket
    emptyDir: {}
  - name: fleet-spiffe-credentials
    csi:
      driver: podcertificate.gke.io
      volumeAttributes:
        signerName: spiffe.gke.io/fleet-svid
        trustDomain: <fleet-project>/svc.id.goog
```

Replace `<registry>/<image>:<tag>`, `<your-workload-image>`, and `<fleet-project>` with your values.

### Testing with grpcurl

Using the pod example above, exec into the `main` container and install `grpcurl`:

```bash
kubectl exec -n debug example -c main -- bash -c '
  curl -sSL https://github.com/fullstorydev/grpcurl/releases/download/v1.9.3/grpcurl_1.9.3_linux_amd64.tar.gz \
    | tar -xz -C /usr/local/bin grpcurl
'
```

Then test the header enforcement and SVID fetch:

```bash
# Missing header → InvalidArgument
kubectl exec -n debug example -c main -- \
  grpcurl -plaintext \
  unix:///run/spiffe/workload.sock \
  SpiffeWorkloadAPI/FetchX509SVID

# With required header → streams SVID response
kubectl exec -n debug example -c main -- \
  grpcurl -plaintext \
  -H 'workload.spiffe.io: true' \
  unix:///run/spiffe/workload.sock \
  SpiffeWorkloadAPI/FetchX509SVID
```
