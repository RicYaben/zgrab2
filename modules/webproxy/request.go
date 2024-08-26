package webproxy

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/url"
	"slices"

	"github.com/zmap/zgrab2/lib/http"
)

func NewRequestBuilder(method, url string, slug bool, headers http.Header) *RequestBuilder {
	b := &RequestBuilder{
		slug: slug,
	}

	b.SetMethod(method)
	b.SetEndpoint(url)
	b.SetHeaders(headers)
	return b
}

type RequestBuilder struct {
	method  string
	url     *url.URL
	headers http.Header
	slug    bool
}

func (b *RequestBuilder) SetEndpoint(uri string) *RequestBuilder {
	u, err := url.Parse(uri)
	if err != nil {
		host, port, err := net.SplitHostPort(uri)
		if err != nil {
			// If SplitHostPort fails, it might be because there is no port
			host = uri
			port = "80"
		}

		// Attempt to handle input as a plain host (domain or IP without scheme)
		if ip := net.ParseIP(host); ip == nil {
			log.Fatalf("uri %s not a valid address", host)
		}
		u = &url.URL{Host: net.JoinHostPort(host, port)}
	}

	if u.Scheme == "" {
		u.Scheme = "http"
	}

	b.url = u
	return b
}

func (b *RequestBuilder) SetParams(slug bool) *RequestBuilder {
	b.slug = slug
	return b
}

func (b *RequestBuilder) SetMethod(method string) *RequestBuilder {
	allowed := []string{"GET", "POST"} // This is sufficient for proxies

	// Set the request builder
	if len(method) == 0 {
		b.method = "POST"
		return b
	}

	if !slices.Contains(allowed, method) {
		panic(fmt.Errorf("method not allowed: %s", method))
	}
	b.method = method
	return b
}

func (builder *RequestBuilder) SetHeaders(headers http.Header) {
	builder.headers = http.Header{
		"Accept":       {"*/*"},
		"Content-Type": {"application/x-www-form-urlencoded"},
	}

	if headers == nil {
		return
	}

	for k, v := range headers {
		builder.headers[k] = v
	}
}

func (builder *RequestBuilder) Build(tokenHash string) (*http.Request, error) {
	t := fmt.Sprintf("token=%s", tokenHash)
	req, err := http.NewRequest(builder.method, builder.url.String(), bytes.NewBufferString(t))
	if err != nil {
		return nil, fmt.Errorf("RequestBuilder.Build(): failed to create request: %v", err)
	}

	// Slug token if needed
	if builder.slug {
		q := req.URL.Query()
		q.Add("token", tokenHash)
		req.URL.RawQuery = q.Encode()
	}

	// Add the headers
	// The constructor does not add any header.
	req.Header = builder.headers
	return req, nil
}
