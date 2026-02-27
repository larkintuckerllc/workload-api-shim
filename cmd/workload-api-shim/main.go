package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"

	workloadv1 "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/larkintuckerllc/workload-api-shim/internal/shimserver"
)

const workloadHeader = "workload.spiffe.io"

func workloadHeaderUnaryInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md.Get(workloadHeader)) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "missing required header: %s", workloadHeader)
	}
	return handler(ctx, req)
}

func workloadHeaderStreamInterceptor(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	md, ok := metadata.FromIncomingContext(ss.Context())
	if !ok || len(md.Get(workloadHeader)) == 0 {
		return status.Errorf(codes.InvalidArgument, "missing required header: %s", workloadHeader)
	}
	return handler(srv, ss)
}

func main() {
	socketPath := flag.String("socket-path", "/tmp/spiffe-workload-api.sock", "Unix domain socket path")
	credsDir := flag.String("creds-dir", "/var/run/secrets/workload-spiffe-credentials", "Directory containing SPIFFE credential files")
	flag.Parse()

	os.Remove(*socketPath)

	lis, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", *socketPath, err)
	}

	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(workloadHeaderUnaryInterceptor),
		grpc.ChainStreamInterceptor(workloadHeaderStreamInterceptor),
	)
	workloadv1.RegisterSpiffeWorkloadAPIServer(srv, shimserver.New(*credsDir))

	log.Printf("serving SPIFFE Workload API on unix://%s", *socketPath)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
