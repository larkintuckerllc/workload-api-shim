package shimserver

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	workloadv1 "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ShimServer implements the SPIFFE Workload API by reading credentials from disk.
type ShimServer struct {
	workloadv1.UnimplementedSpiffeWorkloadAPIServer
	credsDir string
}

// New creates a ShimServer that reads credentials from credsDir.
func New(credsDir string) *ShimServer {
	return &ShimServer{credsDir: credsDir}
}

// loadPEMDERs decodes all PEM blocks in the named file and returns each block as raw DER bytes.
func (s *ShimServer) loadPEMDERs(name string) ([][]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.credsDir, name))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	var ders [][]byte
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		ders = append(ders, block.Bytes)
	}
	return ders, nil
}

// loadPrivateKeyPKCS8DER reads a PEM private key and returns it as PKCS#8 DER,
// converting EC or RSA keys if necessary.
func (s *ShimServer) loadPrivateKeyPKCS8DER(name string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.credsDir, name))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", name)
	}
	switch block.Type {
	case "PRIVATE KEY":
		return block.Bytes, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}
		return x509.MarshalPKCS8PrivateKey(key)
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA private key: %w", err)
		}
		return x509.MarshalPKCS8PrivateKey(key)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q in %s", block.Type, name)
	}
}

// trustBundlesFile mirrors the on-disk trust_bundles.json format.
type trustBundlesFile struct {
	TrustDomains map[string]trustDomainEntry `json:"trust_domains"`
}

type trustDomainEntry struct {
	Keys           []trustKey `json:"keys"`
	SpiffeSequence int64      `json:"spiffe_sequence"`
}

type trustKey struct {
	Use string   `json:"use"`
	Kty string   `json:"kty"`
	Crv string   `json:"crv"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	X5C []string `json:"x5c"`
}

// loadTrustBundles parses trust_bundles.json from the credentials directory.
func (s *ShimServer) loadTrustBundles() (*trustBundlesFile, error) {
	data, err := os.ReadFile(filepath.Join(s.credsDir, "trust_bundles.json"))
	if err != nil {
		return nil, fmt.Errorf("read trust_bundles.json: %w", err)
	}
	var tb trustBundlesFile
	if err := json.Unmarshal(data, &tb); err != nil {
		return nil, fmt.Errorf("parse trust_bundles.json: %w", err)
	}
	return &tb, nil
}

// concatDERs concatenates a slice of DER byte slices into a single byte slice.
func concatDERs(ders [][]byte) []byte {
	var out []byte
	for _, d := range ders {
		out = append(out, d...)
	}
	return out
}

// FetchX509SVID streams the X.509 SVID and holds the stream open until the client disconnects.
func (s *ShimServer) FetchX509SVID(_ *workloadv1.X509SVIDRequest, stream workloadv1.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	certDERs, err := s.loadPEMDERs("certificates.pem")
	if err != nil {
		return status.Errorf(codes.Internal, "load certificates: %v", err)
	}
	if len(certDERs) == 0 {
		return status.Error(codes.Internal, "no certificates found in certificates.pem")
	}

	keyDER, err := s.loadPrivateKeyPKCS8DER("private_key.pem")
	if err != nil {
		return status.Errorf(codes.Internal, "load private key: %v", err)
	}

	caDERs, err := s.loadPEMDERs("ca_certificates.pem")
	if err != nil {
		return status.Errorf(codes.Internal, "load CA certificates: %v", err)
	}

	leaf, err := x509.ParseCertificate(certDERs[0])
	if err != nil {
		return status.Errorf(codes.Internal, "parse leaf certificate: %v", err)
	}
	if len(leaf.URIs) == 0 {
		return status.Error(codes.Internal, "leaf certificate has no URI SANs")
	}
	spiffeID := leaf.URIs[0].String()

	resp := &workloadv1.X509SVIDResponse{
		Svids: []*workloadv1.X509SVID{
			{
				SpiffeId:    spiffeID,
				X509Svid:    concatDERs(certDERs),
				X509SvidKey: keyDER,
				Bundle:      concatDERs(caDERs),
			},
		},
	}
	if err := stream.Send(resp); err != nil {
		return err
	}

	<-stream.Context().Done()
	return nil
}

// FetchX509Bundles streams the X.509 trust bundle map and holds the stream open until the client disconnects.
func (s *ShimServer) FetchX509Bundles(_ *workloadv1.X509BundlesRequest, stream workloadv1.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	certDERs, err := s.loadPEMDERs("certificates.pem")
	if err != nil {
		return status.Errorf(codes.Internal, "load certificates: %v", err)
	}
	if len(certDERs) == 0 {
		return status.Error(codes.Internal, "no certificates found in certificates.pem")
	}

	leaf, err := x509.ParseCertificate(certDERs[0])
	if err != nil {
		return status.Errorf(codes.Internal, "parse leaf certificate: %v", err)
	}
	if len(leaf.URIs) == 0 {
		return status.Error(codes.Internal, "leaf certificate has no URI SANs")
	}
	localTD := "spiffe://" + leaf.URIs[0].Host

	caDERs, err := s.loadPEMDERs("ca_certificates.pem")
	if err != nil {
		return status.Errorf(codes.Internal, "load CA certificates: %v", err)
	}

	bundles := map[string][]byte{
		localTD: concatDERs(caDERs),
	}

	tb, err := s.loadTrustBundles()
	if err != nil {
		return status.Errorf(codes.Internal, "load trust bundles: %v", err)
	}

	for domain, entry := range tb.TrustDomains {
		tdKey := "spiffe://" + domain
		if tdKey == localTD {
			continue
		}
		var ders [][]byte
		for _, key := range entry.Keys {
			if key.Use != "x509-svid" {
				continue
			}
			for _, b64cert := range key.X5C {
				der, err := base64.StdEncoding.DecodeString(b64cert)
				if err != nil {
					return status.Errorf(codes.Internal, "decode x5c entry for domain %s: %v", domain, err)
				}
				ders = append(ders, der)
			}
		}
		if len(ders) > 0 {
			bundles[tdKey] = concatDERs(ders)
		}
	}

	resp := &workloadv1.X509BundlesResponse{
		Bundles: bundles,
	}
	if err := stream.Send(resp); err != nil {
		return err
	}

	<-stream.Context().Done()
	return nil
}

// FetchJWTBundles streams the JWT bundle map (currently empty — no jwt-svid keys in credential files)
// and holds the stream open until the client disconnects.
func (s *ShimServer) FetchJWTBundles(_ *workloadv1.JWTBundlesRequest, stream workloadv1.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	tb, err := s.loadTrustBundles()
	if err != nil {
		return status.Errorf(codes.Internal, "load trust bundles: %v", err)
	}

	bundles := make(map[string][]byte)
	for domain, entry := range tb.TrustDomains {
		var keys []json.RawMessage
		for _, key := range entry.Keys {
			if key.Use != "jwt-svid" {
				continue
			}
			b, err := json.Marshal(key)
			if err != nil {
				return status.Errorf(codes.Internal, "marshal jwt key for domain %s: %v", domain, err)
			}
			keys = append(keys, b)
		}
		if len(keys) == 0 {
			continue
		}
		jwks := struct {
			Keys []json.RawMessage `json:"keys"`
		}{Keys: keys}
		jwksJSON, err := json.Marshal(jwks)
		if err != nil {
			return status.Errorf(codes.Internal, "marshal jwks for domain %s: %v", domain, err)
		}
		bundles["spiffe://"+domain] = jwksJSON
	}

	resp := &workloadv1.JWTBundlesResponse{
		Bundles: bundles,
	}
	if err := stream.Send(resp); err != nil {
		return err
	}

	<-stream.Context().Done()
	return nil
}

// FetchJWTSVID is not supported — no JWT signing keys are present in the credential files.
func (s *ShimServer) FetchJWTSVID(_ context.Context, _ *workloadv1.JWTSVIDRequest) (*workloadv1.JWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "JWT SVIDs are not supported by this shim")
}

// ValidateJWTSVID is not supported — no JWT signing keys are present in the credential files.
func (s *ShimServer) ValidateJWTSVID(_ context.Context, _ *workloadv1.ValidateJWTSVIDRequest) (*workloadv1.ValidateJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "JWT SVID validation is not supported by this shim")
}
