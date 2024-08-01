package request

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/zmap/zgrab2/lib/http"
)

type HttpRequestBuilder interface {
	setUrl(url string)
	setMethod(method string) error
	setHeaders(headers http.Header)
	Build(body string) (*http.Request, error)
}

func NewHttpRequestBuilder(method, url string, headers http.Header, slug bool) (HttpRequestBuilder, error) {
	builder := new(httpProxyRequestBuilder)

	err := builder.setMethod(method)
	if err != nil {
		return nil, err
	}

	builder.setUrl(url)
	builder.setHeaders(headers)
	builder.setSlugToken(slug)

	return builder, nil
}

type httpProxyRequestBuilder struct {
	method  string
	url     *url.URL
	headers http.Header
	slug    bool
}

func (builder *httpProxyRequestBuilder) setUrl(uri string) {
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
			panic("uri %s not a valid address")
		}
		u = &url.URL{Host: net.JoinHostPort(host, port)}
	}

	if u.Scheme == "" {
		u.Scheme = "http" // Default scheme if none is provided
	}

	builder.url = u
}

func (builder *httpProxyRequestBuilder) setSlugToken(slug bool) *httpProxyRequestBuilder {
	builder.slug = slug
	return builder
}

func (builder *httpProxyRequestBuilder) setMethod(method string) error {
	allowed := []string{"GET", "POST"} // This is sufficient for proxies
	for _, val := range allowed {
		if val == method {
			builder.method = method
			return nil
		}
	}
	return fmt.Errorf("method not allowed: %s", method)
}

func (builder *httpProxyRequestBuilder) setHeaders(headers http.Header) {
	builder.headers = http.Header{
		"Accept":           {"*/*"},
		"Proxy-Connection": {"close"},
		"Cache-Control":    {"no-store"},
	}

	if headers == nil {
		return
	}

	for k, v := range headers {
		builder.headers[k] = v
	}
}

func (builder *httpProxyRequestBuilder) Build(token string) (*http.Request, error) {
	// Create the request
	req, err := http.NewRequest(builder.method, builder.url.String(), strings.NewReader(token))
	if err != nil {
		return nil, err
	}

	// Slug token if needed
	if builder.slug {
		q := req.URL.Query()
		q.Add("token", token)
		req.URL.RawQuery = q.Encode()
	}

	// Add the headers
	// The constructor does not add any header.
	req.Header = builder.headers
	return req, nil
}
