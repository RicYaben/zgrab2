package scan

import (
	"time"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
)

type ScanBuilder interface {
	setTransport(int, bool)
	setClient(string, time.Duration)
	Build(target zgrab2.ScanTarget) Scan
}

func NewProxyHttpScanBuilder(maxRedirects int, rawHeaders bool, userAgent string, timeout time.Duration, maxSize int) ScanBuilder {
	builder := new(httpProxyScanBuilder)

	builder.setTransport(maxRedirects, rawHeaders)
	builder.setClient(userAgent, timeout)
	builder.setMaxSize(maxSize)

	return builder
}

type httpProxyScanBuilder struct {
	client    *http.Client
	transport *http.Transport
	maxSize   int64
}

func (builder *httpProxyScanBuilder) setTransport(maxRedirects int, rawHeaders bool) {
	builder.transport = &http.Transport{
		DisableKeepAlives:  false,
		DisableCompression: false,
		MaxIdleConns:       maxRedirects,
		RawHeaderBuffer:    rawHeaders,
	}
}

func (builder *httpProxyScanBuilder) setClient(userAgent string, timeout time.Duration) {

	builder.client = &http.Client{
		UserAgent: userAgent,
		Timeout:   timeout,
		Transport: builder.transport,
		Jar:       nil,
	}
}

func (builder *httpProxyScanBuilder) setMaxSize(maxSize int) {
	builder.maxSize = int64(maxSize) * 1024
}

func (builder *httpProxyScanBuilder) Build(target zgrab2.ScanTarget) Scan {
	return NewHTTPScan(target, builder.client, builder.maxSize)
}
