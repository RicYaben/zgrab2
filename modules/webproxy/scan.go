package webproxy

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
	"golang.org/x/net/html/charset"
	"golang.org/x/net/proxy"
)

type Scan struct {
	target  *zgrab2.ScanTarget
	scanner *Scanner
	client  *http.Client
	scheme  string
	maxRead int64
	proxy   *url.URL

	deadline    time.Time
	connections []net.Conn

	results Results
}

// Attempt to decode the body of a response
func readBody(contentType string, body io.ReadCloser, maxReadLen int64) (string, []byte, error) {
	bodyBytes, err := io.ReadAll(io.LimitReader(body, maxReadLen))
	if err != nil && err != io.EOF {
		return "", nil, err
	}

	// Copy the content we want to read and build the decoder
	encoder, encoding, certain := charset.DetermineEncoding(bodyBytes, contentType)

	bodyText := ""
	decodedSuccessfully := false
	decoder := encoder.NewDecoder()

	if certain || encoding != "windows-1252" {
		if decoded, decErr := decoder.Bytes(bodyBytes); decErr == nil {
			bodyText = string(decoded)
			decodedSuccessfully = true
		}
	}

	if !decodedSuccessfully {
		bodyText = string(bodyBytes)
	}

	// Calculate the hash of the body
	m := sha256.New()
	m.Write(bodyBytes)
	h := m.Sum(nil)

	return bodyText, h, nil
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

func (scan *Scan) socks5DialContext() (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	u, err := scan.getProxyURL()
	if err != nil {
		return nil, err
	}

	socksDialer, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}

	dc := socksDialer.(interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	})

	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		timeoutContext, _ := context.WithTimeout(ctx, scan.client.Timeout)
		conn, err := dc.DialContext(scan.withDeadlineContext(timeoutContext), network, address)
		if err != nil {
			return nil, err
		}

		scan.connections = append(scan.connections, conn)
		return conn, nil
	}, nil
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

func (scan *Scan) getProxyURL() (*url.URL, error) {
	host := scan.target.Domain
	if host == "" {
		host = scan.target.IP.String()
	}

	port := scan.target.Port
	if port == nil {
		port = &scan.scanner.config.BaseFlags.Port
	}

	addr := fmt.Sprintf("%s://%s:%d", scan.scheme, host, *port)
	return url.Parse(addr)
}

// Note: `scan.target` is the proxy.
func (scan *Scan) SetProxyUrl() error {
	proxy, err := scan.getProxyURL()
	if err != nil {
		return err
	}
	scan.proxy = proxy

	transport := scan.client.Transport.(*http.Transport)
	switch scan.scheme {
	case "https":
		transport.DialTLS = scan.getTLSDialer(scan.target)
		transport.Proxy = http.ProxyURL(proxy)
	case "socks5":
		// This dialer does not need the Proxy
		// value in the transport, since it makes
		// connections through the proxy already.
		dialCtx, err := scan.socks5DialContext()
		if err != nil {
			return err
		}
		transport.DialContext = dialCtx
	default:
		transport.DialContext = scan.dialContext
		transport.Proxy = http.ProxyURL(proxy)
	}

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
	hash := md5.New()
	hash.Write([]byte(tkn))
	tknHash := fmt.Sprintf("%x", hash.Sum(nil))
	req, err := scan.scanner.requestBuilder.Build(tknHash)
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}

	// Send the request
	resp, err := scan.client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	// Put the response as is
	scan.results.Token = tkn
	scan.results.TokenMD5 = tknHash
	scan.results.Response = resp
	scan.results.Target = scan.proxy.String()
	if err != nil {
		if urlError, ok := err.(*url.Error); ok {
			err = urlError.Err
		}
		return zgrab2.DetectScanError(err)
	}

	// Parse the body until the assigned number of bytes to read
	var maxReadLen int64 = scan.maxRead
	if resp.ContentLength >= 0 && resp.ContentLength < maxReadLen {
		maxReadLen = resp.ContentLength
	}

	cType := resp.Header.Get("content-type")
	bodyText, h, err := readBody(cType, resp.Body, maxReadLen)
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}
	// Assign the parsed body
	scan.results.Response.BodyText = bodyText
	scan.results.Response.BodySHA256 = h
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
	builder.SetMaxRead()
	return builder
}

type ScanBuilder struct {
	scanner *Scanner
	client  http.Client
	maxRead int64
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
		b.maxRead = 4096
	// it may be that we do not want to read anything.
	case -1:
		b.maxRead = 0
	default:
		b.maxRead = mr
	}
	return b
}

func (b *ScanBuilder) Build(t *zgrab2.ScanTarget, scheme string) *Scan {
	scan := &Scan{
		scanner:  b.scanner,
		target:   t,
		scheme:   scheme,
		deadline: time.Now().Add(b.client.Timeout),
		client:   &b.client,
		maxRead:  b.maxRead,
	}
	return scan
}
