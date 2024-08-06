package webproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
	"golang.org/x/net/html/charset"
)

type Scan struct {
	target  *zgrab2.ScanTarget
	scanner *Scanner
	client  *http.Client
	useTLS  bool
	maxRead int64
	proxy   *url.URL

	deadline    time.Time
	connections []net.Conn

	Results Results
}

// Attempt to decode the body of a response
func readBody(contentType string, body io.ReadCloser, maxReadLen int64) (string, []byte, error) {

	// Copy the content we want to read and build the decoder
	buf := new(bytes.Buffer)
	io.CopyN(buf, body, maxReadLen)
	encoder, encoding, certain := charset.DetermineEncoding(buf.Bytes(), contentType)
	decoder := encoder.NewDecoder()

	// Return early if the body was empty. No reason to go on from here.
	// A bit weird, but it may happen!
	bts := buf.Bytes()
	if len(bts) == 0 {
		return "", nil, nil
	}

	var b strings.Builder
	switch {
	//"windows-1252" is the default value and will likely not decode correctly
	case certain || encoding != "windows-1252":
		decoded, err := decoder.Bytes(bts)
		if err != nil {
			return "", nil, fmt.Errorf("error while decoding the body: %v", err)
		}

		b.Write(decoded)
	default:
		b.Write(bts)
	}

	bString := b.String()
	// re-enforce readlen
	if int64(len(bString)) > maxReadLen {
		bString = bString[:int(maxReadLen)]
	}

	// Calculate the hash of the body
	m := sha256.New()
	m.Write(bts)
	h := m.Sum(nil)

	return bString, h, nil
}

// Get a context whose deadline is the earliest of the context's deadline (if it has one) and the
// global scan deadline.
func (scan *Scan) withDeadlineContext(ctx context.Context) context.Context {
	ctxDeadline, ok := ctx.Deadline()
	scanDeadline := scan.deadline
	if !ok || scanDeadline.Before(ctxDeadline) {
		// NOTE: this leaks, currently handled by `scan.Cleanup`
		ret, _ := context.WithDeadline(ctx, scanDeadline)
		return ret
	}
	return ctx
}

// Dial a connection using the configured timeouts, as well as the global deadline, and on success,
// add the connection to the list of connections to be cleaned up.
func (scan *Scan) dialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	timeout := scan.client.Timeout
	dialer := zgrab2.GetTimeoutConnectionDialer(timeout)

	switch network {
	case "tcp", "tcp4":
		// If the scan is for a specific IP, and a domain name is provided, we
		// don't want to just let the http library resolve the domain.  Create
		// a fake resolver that we will use, that always returns the IP we are
		// given to scan.
		if scan.target.IP != nil && scan.target.Domain != "" {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				log.Errorf("http/scanner.go dialContext: unable to split host:port '%s'", addr)
				log.Errorf("No fake resolver, IP address may be incorrect: %s", err)
				break
			}

			// In the case of redirects, we don't want to blindly use the
			// IP we were given to scan, however.  Only use the fake
			// resolver if the domain originally specified for the scan
			// target matches the current address being looked up in this
			// DialContext.
			if host == scan.target.Domain {
				resolver, err := zgrab2.NewFakeResolver(scan.target.IP.String())
				if err != nil {
					return nil, err
				}
				dialer.Dialer.Resolver = resolver
			}
		}
	}

	// NOTE: This leaks
	timeoutContext, _ := context.WithTimeout(context.Background(), timeout)

	conn, err := dialer.DialContext(scan.withDeadlineContext(timeoutContext), network, addr)
	if err != nil {
		return nil, err
	}
	scan.connections = append(scan.connections, conn)
	return conn, nil
}

// getTLSDialer returns a Dial function that connects using the
// zgrab2.GetTLSConnection()
func (scan *Scan) getTLSDialer(t *zgrab2.ScanTarget) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		outer, err := scan.dialContext(context.Background(), network, addr)
		if err != nil {
			return nil, err
		}
		cfg, err := scan.scanner.config.TLSFlags.GetTLSConfigForTarget(t)
		if err != nil {
			return nil, err
		}

		// Set SNI server name on redirects unless --server-name was used (issue #300)
		//  - t.Domain is always set to the *original* Host so it's not useful for setting SNI
		//  - host is the current target of the request in this context; this is true for the
		//    initial request as well as subsequent requests caused by redirects
		//  - scan.scanner.config.ServerName is the value from --server-name if one was specified

		// If SNI is enabled and --server-name is not set, use the target host for the SNI server name
		if !scan.scanner.config.NoSNI && scan.scanner.config.ServerName == "" {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				log.Errorf("getTLSDialer(): Something went wrong splitting host/port '%s': %s", addr, err)
			}
			// RFC4366: Literal IPv4 and IPv6 addresses are not permitted in "HostName"
			if i := net.ParseIP(host); i == nil {
				cfg.ServerName = host
			}
		}

		tlsConn := scan.scanner.config.TLSFlags.GetWrappedConnection(outer, cfg)

		// lib/http/transport.go fills in the TLSLog in the http.Request instance(s)
		err = tlsConn.Handshake()
		return tlsConn, err
	}
}

func (scan *Scan) SetProxyUrl() error {
	transport := scan.client.Transport.(*http.Transport)
	transport.DialContext = scan.dialContext

	host := scan.target.Domain
	if host == "" {
		host = scan.target.IP.String()
	}

	port := scan.target.Port
	if port == nil {
		port = &scan.scanner.config.BaseFlags.Port
	}

	var schema string
	switch {
	case scan.useTLS:
		schema = "https"
		transport.DialTLS = scan.getTLSDialer(scan.target)
	default:
		schema = "http"
	}

	addr := fmt.Sprintf("%s://%s:%d", schema, host, *port)
	proxy, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf(`failed to parse proxy address "%s": %v`, addr, err)
	}
	scan.proxy = proxy
	transport.Proxy = http.ProxyURL(proxy)

	return nil
}

func (scan *Scan) Grab() *zgrab2.ScanError {
	if err := scan.SetProxyUrl(); err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	// Build the token (body) for the proxy address so we can verify later at the destination
	tkn, err := scan.scanner.tokenBuilder.GenerateToken(scan.proxy.String())
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}

	// Build the request
	req, err := scan.scanner.requestBuilder.Build(tkn)
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}

	// Send the request
	resp, err := scan.client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	// Put the response as is
	scan.Results.Token = tkn
	scan.Results.Response = resp
	scan.Results.Target = scan.proxy.String()
	if err != nil {
		if urlError, ok := err.(*url.Error); ok {
			err = urlError.Err
		}
		return zgrab2.DetectScanError(err)
	}

	// NOTE: we will not handle responses with unknown content length
	// or supposedly "empty". This can be done offline
	if resp.ContentLength <= 0 {
		return nil
	}

	// Parse the body until the assigned number of bytes to read
	maxReadLen := scan.maxRead
	if resp.ContentLength < maxReadLen {
		maxReadLen = resp.ContentLength
	}

	cType := resp.Header.Get("content-type")
	bodyText, h, err := readBody(cType, resp.Body, maxReadLen)
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	// Assign the parsed body
	resp.BodyText = bodyText
	resp.BodySHA256 = h

	return nil
}

func (scan *Scan) Cleanup() {
	if scan.connections != nil {
		for _, conn := range scan.connections {
			defer conn.Close()
		}
		scan.connections = nil
	}
}

func NewScanBuilder(scanner *Scanner) *ScanBuilder {
	builder := &ScanBuilder{
		scanner: scanner,
	}

	builder.SetClient()
	return builder
}

type ScanBuilder struct {
	scanner *Scanner
	client  http.Client
	maxRead int64
}

func (b *ScanBuilder) getTLSDialer(t *zgrab2.ScanTarget) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		log.Fatal("not implemented yet")
		return nil, nil
	}
}

func (b *ScanBuilder) SetClient() *ScanBuilder {
	t := b.scanner.config.Timeout
	if t == 0 {
		t = 10 * time.Second
	}

	b.client = http.Client{
		UserAgent: b.scanner.config.UserAgent,
		Timeout:   t,
		Transport: &http.Transport{
			DisableKeepAlives:   false,
			DisableCompression:  false,
			MaxIdleConnsPerHost: b.scanner.config.MaxRedirects,
			RawHeaderBuffer:     b.scanner.config.RawHeaders,
		},
		Jar: nil,
		// TODO: add check redirects?
	}
	return b
}

func (b *ScanBuilder) SetMaxRead() *ScanBuilder {
	mr := int64(b.scanner.config.MaxSize)
	switch mr {
	// this is a replacement for nil values, i.e., default
	case 0:
		b.maxRead = 256
	// it may be that we do not want to read anything.
	case -1:
		b.maxRead = 0
	default:
		b.maxRead = mr
	}
	return b
}

func (b *ScanBuilder) Build(t *zgrab2.ScanTarget, useTLS bool) *Scan {
	scan := &Scan{
		scanner:  b.scanner,
		target:   t,
		useTLS:   useTLS,
		deadline: time.Now().Add(b.client.Timeout),
		client:   &b.client,
		maxRead:  b.maxRead,
	}

	// TODO: handle SOCKS
	// if useSOCKS {}
	return scan
}
