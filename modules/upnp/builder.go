/*
This package contains an SSDP request builder.
The request handler was inspired on https://github.com/huin/goupnp/blob/main/httpu/httpu.go
*/
package upnp

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/zmap/zgrab2/lib/http"
	"golang.org/x/exp/slices"
)

type SSDPHandler struct {
	request *http.Request
}

func NewSSDPHandler(req *http.Request) *SSDPHandler {
	return &SSDPHandler{request: req}
}

func (handler *SSDPHandler) Encode() ([]byte, error) {
	var buff bytes.Buffer

	req := handler.request

	// As pointed out in the goupnp project, dumping the request directly creates
	// duplicate and extra headers that may confuse the target.
	// This writes just the request and the headers instead.
	reqLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	if _, err := buff.Write([]byte(reqLine)); err != nil {
		return nil, err
	}

	if err := req.Header.Write(&buff); err != nil {
		return nil, err
	}

	if _, err := buff.Write([]byte("\r\n")); err != nil {
		return nil, err
	}

	return buff.Bytes(), nil

}

func (handler *SSDPHandler) ReadHttpResponse(conn net.Conn) (*http.Response, error) {
	// NOTE: 3 seconds is an arbitrary amount of time to wait.
	// In most cases, 1s should be more than enough. While stress testing
	// I saw delays of 1-2 seconds (up to 5 in rare occasions)
	err := conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		return nil, err
	}

	// 1k should be enough for a M-SEARCH request, which only contains headers
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	respBuf := bufio.NewReader(bytes.NewBuffer(buf[:n]))
	return http.ReadResponse(respBuf, handler.request)
}

type SSDPBuilder interface {
	setUserAgent(userAgent string) error
	setMethod(method string) error
	setMan(man string)
	setST(st string) error
	Build(target string, port uint16) *SSDPHandler
}

func NewSSDPBuilder(method, userAgent, man, st string) (SSDPBuilder, error) {
	msg := &ssdpBuilder{}

	err := msg.setMethod(method)
	if err != nil {
		return nil, err
	}

	err = msg.setUserAgent(userAgent)
	if err != nil {
		return nil, err
	}

	err = msg.setST(st)
	if err != nil {
		return nil, err
	}

	msg.setMan(man)
	return msg, nil
}

type ssdpBuilder struct {
	// First Line
	method string
	// Headers
	userAgent string
	man       string
	st        string
}

func (b *ssdpBuilder) setUserAgent(ua string) error {
	if len(ua) == 0 {
		return fmt.Errorf(`invalid SSDP user-agent "%s"`, ua)
	}

	b.userAgent = ua
	return nil
}

// This method accepts a choice of M-SEARCH or NOTIFY as the method
// to use while probing UPnP devices. M-SEARCH should be used when
// we want to identify exposed devices, while NOTIFY can be used to
// identify devices that accept modifying requests from unknown hosts.
// Use NOTIFY with care and DO NOT use this value lightly, you may
// break something!
func (b *ssdpBuilder) setMethod(method string) error {
	if !slices.Contains([]string{"M-SEARCH", "NOTIFY"}, method) {
		return fmt.Errorf(`invalid SSDP method "%s"`, method)
	}

	b.method = method
	return nil
}

func (b *ssdpBuilder) setMan(man string) {
	if man != "ssdp:discover" {
		fmt.Println(fmt.Errorf(
			`MAN value in SSDP should be "ssdp:discover". 
			Using "%s" instead`, man))
	}
	b.man = fmt.Sprintf(`"%s"`, man)
}

// Validate and set the ST header value.
// Note: while the "ssdp:all" value should return larger and more interesting
// responses, most devices will refuse to respond to this value.
// "upnp:rootdevice" yielded the most results while sampling 1% of the
// Internet with different values and combinations. Use with care and refer
// to the UPnP documentation when in doubt.
func (b *ssdpBuilder) setST(st string) error {
	if strings.HasPrefix(st, "ssdp:") ||
		strings.HasPrefix(st, "upnp:") ||
		strings.HasPrefix(st, "uuid:") ||
		strings.HasPrefix(st, "urn:") {
		b.st = st
		return nil
	}
	return fmt.Errorf("invalid ST %s. Check the UPnP documentation for valid identifiers", st)
}

func (b *ssdpBuilder) Build(target string, port uint16) *SSDPHandler {
	host := fmt.Sprintf("%s:%d", target, port)
	req := &http.Request{
		Method: b.method,
		Host:   host,
		URL:    &url.URL{Opaque: "*"},
		Header: http.Header{
			"HOST":       []string{host},
			"MAN":        []string{b.man},
			"ST":         []string{b.st},
			"USER-AGENT": []string{b.userAgent},
		},
	}

	return NewSSDPHandler(req)
}
