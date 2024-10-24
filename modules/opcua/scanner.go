package opcua

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags

	Uri           string `json:"uri" default:"urn:opcua:zgrab" description:"Client URI for anonymous authentication"`
	CertHost      string `json:"cert-host" default:"localhost" description:"Host certificate holder"`
	Endpoint      string `json:"endpoint" description:"Path endpoint in the server"`
	EndpointLimit uint   `json:"endpoint-limit" description:"Limit the number of nodes to interact with while browsing"`
	BrowseDepth   uint   `json:"browse-depth" description:"Browse nesting level, one level is enough to prove access and retrival. Default: 0; Max: 10; Recommended: 1;"`

	/*
		# TODO FIXME [17/10/2024]: This may make sense in the future. Implement it
		# Right now is not a priority, but others may want to specify the scheme directly
		UseHTTP   bool `json:"use-http" description:"use HTTP"`
		RetryHTTP bool `json:"retry-http"  description:"retry over HTTP"`
		UseTLS    bool `json:"use-tls" description:"Use HTTPS"`
		RetryTLS  bool `json:"retry-tls" description:"retry to connect with TLS"`
	*/
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

type Scanner struct {
	config   *Flags
	LocalKey *rsa.PrivateKey

	certificate []byte
	endpoint    string
}

// GetName implements zgrab2.Scanner.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger implements zgrab2.Scanner.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Init implements zgrab2.Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.endpoint = f.Endpoint

	certPEM, keyPEM, err := generateSelfSignedCert(f.CertHost)
	if err != nil {
		return fmt.Errorf("failed to generate self-signed certificate: %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("error while loading certificate: %v", err)
	}
	scanner.certificate = cert.Certificate[0]
	return nil
}

// InitPerSender implements zgrab2.Scanner.
func (*Scanner) InitPerSender(senderID int) error {
	return nil
}

// Protocol implements zgrab2.Scanner.
func (*Scanner) Protocol() string {
	return "opcua"
}

func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("opcua", "OPC UA module", module.Description(), 4840, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (f *Flags) Validate(args []string) error {
	return nil
}

func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns text uses in the help for this module.
func (module *Module) Description() string {
	return "Probe for devices that speak OPC-UA"
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return ""
}

type scan struct {
	scanner *Scanner
	ctx     context.Context
	cancel  context.CancelFunc

	results   Results
	endpoint  string
	authModes []string
	browser   *browser
}

func (s *scan) setEndpoints(eps []*ua.EndpointDescription) {
	for _, ep := range eps {
		r := newEndpoint(ep)
		s.results.Endpoints = append(s.results.Endpoints, r)
	}
}

func (s *scan) Grab() *zgrab2.ScanError {
	// Get endpoints
	eps, err := opcua.GetEndpoints(s.ctx, s.endpoint)
	if err != nil {
		return zgrab2.DetectScanError(err)
	}
	s.setEndpoints(eps)

	resEps := s.results.Endpoints
	if limit := int(s.scanner.config.EndpointLimit); len(resEps) > limit {
		resEps = resEps[:limit]
	}

	// Authenticate to each endpoints
	for _, r := range resEps {
		s.authAndBrowse(r)
	}
	return nil
}

func (s *scan) getAuth(auth string) (ua.UserTokenType, opcua.Option) {
	// We only care about anonymous or self-signed certificate authentications
	if auth == "anonymous" {
		return ua.UserTokenTypeAnonymous, opcua.AuthAnonymous()
	}

	if auth == "certificate" {
		return ua.UserTokenTypeCertificate, opcua.AuthCertificate(s.scanner.certificate)
	}

	return 0, nil
}

func (s *scan) clientOptions(ep *ua.EndpointDescription, auth string) []opcua.Option {
	authMode, authOption := s.getAuth(auth)
	return []opcua.Option{
		authOption,
		opcua.SecurityFromEndpoint(ep, authMode),
	}
}

func (s *scan) authAndBrowse(r *EndpointResult) {
	ep := r.EndpointDescription

	var authedClient *opcua.Client

	// TODO FIXME: The endpointdescription already tell us which modes does it
	// accept. Use those instead?
	for _, a := range s.authModes {
		ops := s.clientOptions(ep, a)
		client, err := opcua.NewClient(ep.EndpointURL, ops...)
		if err != nil {
			continue
		}
		defer client.Close(s.ctx)

		if err := client.Connect(s.ctx); err != nil {
			continue
		}
		authedClient = client
		r.Authenticated = append(r.Authenticated, a)
	}

	if authedClient != nil {
		select {
		case <-s.ctx.Done():
			return
		default:
			r.Namespaces = authedClient.Namespaces()
			id, _ := ua.ParseNodeID("i=84")
			nodes, err := s.browser.browse(authedClient.Node(id), "", 0)
			if err != nil {
				return
			}
			r.Nodes = nodes
		}
	}
}

func (s *Scanner) newOPCUAscan(ep string) *scan {
	ctx, cancel := context.WithTimeout(context.Background(), s.config.Timeout)
	return &scan{
		scanner:   s,
		ctx:       ctx,
		endpoint:  ep,
		authModes: []string{"anonymous", "certificate"},
		browser:   newBrowser(s.config.BrowseDepth, ctx),
		cancel:    cancel,
	}
}

func (s *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	ep := fmt.Sprintf("opc.tcp://%s:%d", t.Host(), *t.Port)
	ep = strings.Join([]string{ep, s.endpoint}, "/")

	scan := s.newOPCUAscan(ep)
	if err := scan.Grab(); err != nil {
		return err.Unpack(&scan.results)
	}
	return zgrab2.SCAN_SUCCESS, &scan.results, nil
}

func generateSelfSignedCert(host string) ([]byte, []byte, error) {
	// Create a new ECDSA private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Generate a random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Add IP and DNS names
	ip := net.ParseIP(host)
	if ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	// Encode the certificate and private key in PEM format (in-memory)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})
	return certPEM, keyPEMBlock, nil
}
