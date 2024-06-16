package scan

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

type Scan interface {
	Init() error
	Grab(*http.Request) *zgrab2.ScanError
	GetResults() *Results
	Cleanup()
}

type config struct {
	maxRead  int64
	deadline time.Time
}

type scan struct {
	target zgrab2.ScanTarget

	client      *http.Client
	results     Results
	connections []net.Conn

	config *config
}

func NewHTTPScan(target zgrab2.ScanTarget, client *http.Client, maxSize int64) Scan {
	return &scan{
		target: target,
		client: client,
		config: &config{
			maxRead:  maxSize,
			deadline: time.Now().Add(client.Timeout),
		},
	}
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

func (scan *scan) Init() error {
	// Set the dialer
	transport := scan.client.Transport.(*http.Transport)

	addr := fmt.Sprintf("http://%s:%d", scan.target.IP.String(), *scan.target.Port)
	url, err := url.Parse(addr)
	if err != nil {
		return err
	}

	// Put the proxy and start the dialer
	transport.Proxy = http.ProxyURL(url)
	transport.DialContext = scan.newDialContext
	return nil
}

// Get a context whose deadline is the earliest of the context's deadline (if it has one) and the
// global scan deadline.
func (scan *scan) withDeadlineContext(ctx context.Context) context.Context {
	ctxDeadline, ok := ctx.Deadline()
	scanDeadline := scan.config.deadline
	if !ok || scanDeadline.Before(ctxDeadline) {
		ret, _ := context.WithDeadline(ctx, scanDeadline)
		return ret
	}
	return ctx
}

// Dial a connection using the configured timeouts, as well as the global deadline, and on success,
// add the connection to the list of connections to be cleaned up.
func (scan *scan) newDialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	timeout := scan.client.Timeout
	dialer := zgrab2.GetTimeoutConnectionDialer(timeout)

	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
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

	timeoutContext, _ := context.WithTimeout(context.Background(), timeout)

	conn, err := dialer.DialContext(scan.withDeadlineContext(timeoutContext), network, addr)
	if err != nil {
		return nil, err
	}
	scan.connections = append(scan.connections, conn)
	return conn, nil
}

func (scan *scan) Grab(request *http.Request) *zgrab2.ScanError {

	// Send the request
	resp, err := scan.client.Do(request)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	// Put the response as is
	scan.results.Response = resp
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
	maxReadLen := scan.config.maxRead
	if resp.ContentLength < maxReadLen {
		maxReadLen = resp.ContentLength
	}

	cType := resp.Header.Get("content-type")
	bodyText, h, err := readBody(cType, resp.Body, maxReadLen)
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
	}

	// Assign it
	resp.BodyText = bodyText
	resp.BodySHA256 = h

	return nil
}

func (scan *scan) GetResults() *Results {
	return &scan.results
}

func (scan *scan) Cleanup() {
	if scan.connections != nil {
		for _, conn := range scan.connections {
			defer conn.Close()
		}
		scan.connections = nil
	}
}
