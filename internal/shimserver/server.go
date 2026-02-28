package shimserver

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	workloadv1 "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// broadcaster fans out a rotation signal to all subscribed streams.
type broadcaster struct {
	mu   sync.Mutex
	subs map[int]chan struct{}
	next int
}

func newBroadcaster() *broadcaster {
	return &broadcaster{subs: make(map[int]chan struct{})}
}

func (b *broadcaster) subscribe() (int, <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.next
	b.next++
	ch := make(chan struct{}, 1)
	b.subs[id] = ch
	return id, ch
}

func (b *broadcaster) unsubscribe(id int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subs, id)
}

func (b *broadcaster) broadcast() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- struct{}{}:
		default: // drop if subscriber hasn't consumed the previous signal yet
		}
	}
}

// ShimServer implements the SPIFFE Workload API by reading credentials from disk.
type ShimServer struct {
	workloadv1.UnimplementedSpiffeWorkloadAPIServer
	credsDir string
	bcast    *broadcaster
}

// New creates a ShimServer that reads credentials from credsDir and watches
// for credential rotation, pushing updates to all connected streams.
func New(credsDir string) (*ShimServer, error) {
	s := &ShimServer{
		credsDir: credsDir,
		bcast:    newBroadcaster(),
	}
	if err := s.startWatcher(); err != nil {
		return nil, fmt.Errorf("start credential watcher: %w", err)
	}
	return s, nil
}

// startWatcher watches credsDir for file changes and broadcasts to active streams.
// Changes are debounced by 100ms to coalesce rapid multi-file rotation events.
func (s *ShimServer) startWatcher() error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := w.Add(s.credsDir); err != nil {
		w.Close()
		return err
	}
	go func() {
		defer w.Close()
		var debounce *time.Timer
		for {
			select {
			case event, ok := <-w.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					if debounce != nil {
						debounce.Stop()
					}
					debounce = time.AfterFunc(100*time.Millisecond, func() {
						log.Println("credentials rotated, pushing update to connected streams")
						s.bcast.broadcast()
					})
				}
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				log.Printf("credential watcher error: %v", err)
			}
		}
	}()
	return nil
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

// buildX509SVIDResponse reads the current credentials from disk and builds the response.
func (s *ShimServer) buildX509SVIDResponse() (*workloadv1.X509SVIDResponse, error) {
	certDERs, err := s.loadPEMDERs("certificates.pem")
	if err != nil {
		return nil, fmt.Errorf("load certificates: %w", err)
	}
	if len(certDERs) == 0 {
		return nil, fmt.Errorf("no certificates found in certificates.pem")
	}
	keyDER, err := s.loadPrivateKeyPKCS8DER("private_key.pem")
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}
	caDERs, err := s.loadPEMDERs("ca_certificates.pem")
	if err != nil {
		return nil, fmt.Errorf("load CA certificates: %w", err)
	}
	leaf, err := x509.ParseCertificate(certDERs[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	if len(leaf.URIs) == 0 {
		return nil, fmt.Errorf("leaf certificate has no URI SANs")
	}
	return &workloadv1.X509SVIDResponse{
		Svids: []*workloadv1.X509SVID{
			{
				SpiffeId:    leaf.URIs[0].String(),
				X509Svid:    concatDERs(certDERs),
				X509SvidKey: keyDER,
				Bundle:      concatDERs(caDERs),
			},
		},
	}, nil
}

// buildX509BundlesResponse reads the current trust bundles from disk and builds the response.
func (s *ShimServer) buildX509BundlesResponse() (*workloadv1.X509BundlesResponse, error) {
	certDERs, err := s.loadPEMDERs("certificates.pem")
	if err != nil {
		return nil, fmt.Errorf("load certificates: %w", err)
	}
	if len(certDERs) == 0 {
		return nil, fmt.Errorf("no certificates found in certificates.pem")
	}
	leaf, err := x509.ParseCertificate(certDERs[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	if len(leaf.URIs) == 0 {
		return nil, fmt.Errorf("leaf certificate has no URI SANs")
	}
	localTD := "spiffe://" + leaf.URIs[0].Host

	caDERs, err := s.loadPEMDERs("ca_certificates.pem")
	if err != nil {
		return nil, fmt.Errorf("load CA certificates: %w", err)
	}
	bundles := map[string][]byte{localTD: concatDERs(caDERs)}

	tb, err := s.loadTrustBundles()
	if err != nil {
		return nil, fmt.Errorf("load trust bundles: %w", err)
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
					return nil, fmt.Errorf("decode x5c entry for domain %s: %w", domain, err)
				}
				ders = append(ders, der)
			}
		}
		if len(ders) > 0 {
			bundles[tdKey] = concatDERs(ders)
		}
	}
	return &workloadv1.X509BundlesResponse{Bundles: bundles}, nil
}

// buildJWTBundlesResponse reads the current trust bundles from disk and builds the response.
func (s *ShimServer) buildJWTBundlesResponse() (*workloadv1.JWTBundlesResponse, error) {
	tb, err := s.loadTrustBundles()
	if err != nil {
		return nil, fmt.Errorf("load trust bundles: %w", err)
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
				return nil, fmt.Errorf("marshal jwt key for domain %s: %w", domain, err)
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
			return nil, fmt.Errorf("marshal jwks for domain %s: %w", domain, err)
		}
		bundles["spiffe://"+domain] = jwksJSON
	}
	return &workloadv1.JWTBundlesResponse{Bundles: bundles}, nil
}

// FetchX509SVID streams the X.509 SVID and pushes updates whenever credentials rotate.
func (s *ShimServer) FetchX509SVID(_ *workloadv1.X509SVIDRequest, stream workloadv1.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	resp, err := s.buildX509SVIDResponse()
	if err != nil {
		return status.Errorf(codes.Internal, "%v", err)
	}
	if err := stream.Send(resp); err != nil {
		return err
	}

	id, rotated := s.bcast.subscribe()
	defer s.bcast.unsubscribe(id)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-rotated:
			resp, err := s.buildX509SVIDResponse()
			if err != nil {
				log.Printf("FetchX509SVID: reload failed: %v", err)
				continue
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}
}

// FetchX509Bundles streams the X.509 trust bundle map and pushes updates whenever credentials rotate.
func (s *ShimServer) FetchX509Bundles(_ *workloadv1.X509BundlesRequest, stream workloadv1.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	resp, err := s.buildX509BundlesResponse()
	if err != nil {
		return status.Errorf(codes.Internal, "%v", err)
	}
	if err := stream.Send(resp); err != nil {
		return err
	}

	id, rotated := s.bcast.subscribe()
	defer s.bcast.unsubscribe(id)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-rotated:
			resp, err := s.buildX509BundlesResponse()
			if err != nil {
				log.Printf("FetchX509Bundles: reload failed: %v", err)
				continue
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}
}

// FetchJWTBundles streams the JWT bundle map and pushes updates whenever credentials rotate.
func (s *ShimServer) FetchJWTBundles(_ *workloadv1.JWTBundlesRequest, stream workloadv1.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	resp, err := s.buildJWTBundlesResponse()
	if err != nil {
		return status.Errorf(codes.Internal, "%v", err)
	}
	if err := stream.Send(resp); err != nil {
		return err
	}

	id, rotated := s.bcast.subscribe()
	defer s.bcast.unsubscribe(id)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-rotated:
			resp, err := s.buildJWTBundlesResponse()
			if err != nil {
				log.Printf("FetchJWTBundles: reload failed: %v", err)
				continue
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}
}

// FetchJWTSVID is not supported — no JWT signing keys are present in the credential files.
func (s *ShimServer) FetchJWTSVID(_ context.Context, _ *workloadv1.JWTSVIDRequest) (*workloadv1.JWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "JWT SVIDs are not supported by this shim")
}

// ValidateJWTSVID is not supported — no JWT signing keys are present in the credential files.
func (s *ShimServer) ValidateJWTSVID(_ context.Context, _ *workloadv1.ValidateJWTSVIDRequest) (*workloadv1.ValidateJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "JWT SVID validation is not supported by this shim")
}
