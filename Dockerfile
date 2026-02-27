# Build stage — always runs on the host platform; cross-compiles for TARGETARCH.
FROM --platform=$BUILDPLATFORM golang:1.26 AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o workload-api-shim ./cmd/workload-api-shim

# Final stage — minimal distroless image, runs as non-root.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /app/workload-api-shim /workload-api-shim

ENTRYPOINT ["/workload-api-shim"]
