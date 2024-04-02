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
	"net/http"
	"net/url"
	"strings"
	"time"

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
	err := conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 2048)
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
	method string `long:"method" default:"M-SEARCH" description:"Request method"`
	// Headers
	userAgent string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
	man       string `long:"man" default:"ssdp:discover" description:"Extension framework"`
	st        string `long:"st" default:"ssdp:all" description:"Search target"`
}

func (b *ssdpBuilder) setUserAgent(ua string) error {
	if len(ua) == 0 {
		return fmt.Errorf(`invalid SSDP user-agent "%s"`, ua)
	}

	b.userAgent = ua
	return nil
}

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
	b.man = man
}

func (b *ssdpBuilder) setST(st string) error {
	if !strings.HasPrefix(st, "ssdp:") ||
		!strings.HasPrefix(st, "uuid:") ||
		!strings.HasPrefix(st, "urn:") {
		return fmt.Errorf("invalid ST. Check the UPnP documentation for valid identifiers")
	}

	b.st = st
	return nil
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
