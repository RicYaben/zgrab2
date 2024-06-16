package request

import (
	"fmt"
	"strings"

	"github.com/zmap/zgrab2/lib/http"
)

type HttpRequestBuilder interface {
	setUrl(url string)
	setMethod(method string) error
	setHeaders(headers http.Header)
	Build(body string) (*http.Request, error)
}

func NewHttpRequestBuilder(method, url string, headers http.Header) (HttpRequestBuilder, error) {
	builder := new(httpProxyRequestBuilder)

	err := builder.setMethod(method)
	if err != nil {
		return nil, err
	}

	builder.setUrl(url)
	builder.setHeaders(headers)

	return builder, nil
}

type httpProxyRequestBuilder struct {
	method  string
	url     string
	headers http.Header
}

func (builder *httpProxyRequestBuilder) setUrl(url string) {
	if len(url) > 0 {
		builder.url = fmt.Sprintf("http://%s", url)
		return
	}
	builder.url = "/"
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

func (builder *httpProxyRequestBuilder) Build(body string) (*http.Request, error) {

	// Add the body
	var b *strings.Reader
	if len(body) > 0 {
		b = strings.NewReader(body)
	}

	// Create the request
	req, err := http.NewRequest(builder.method, builder.url, b)
	if err != nil {
		return nil, err
	}

	// Add the headers
	// The constructor does not add any header.
	req.Header = builder.headers

	return req, nil
}
