package upnp

import (
	"fmt"
	"strings"

	"golang.org/x/exp/slices"
)

type UPnPBuilder interface {
	setUserAgent(string) error
	setRequestLine(string) error
	setMan(string)
	setST(string) error
	EncodeToString(host string, port uint16) string // Encodes the UPnP message a string
}

func NewUpnpBuilder(requestLine, userAgent, man, st string) (UPnPBuilder, error) {
	msg := &upnpBuilder{}

	err := msg.setRequestLine(requestLine)
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

type upnpBuilder struct {
	// First Line
	requestLine string `long:"request-line" default:"M-SEARCH * HTTP/1.1" description:"Request method"`
	// Headers
	userAgent string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
	man       string `long:"man" default:"ssdp:discover" description:"Extension framework"`
	st        string `long:"st" default:"ssdp:all" description:"Search target"`
}

func (b *upnpBuilder) setUserAgent(ua string) error {
	if len(ua) == 0 {
		return fmt.Errorf(`invalid SSDP user-agent "%s"`, ua)
	}

	b.userAgent = ua
	return nil
}

func (b *upnpBuilder) setRequestLine(req string) error {
	f := strings.Fields(req)
	if len(f) != 3 {
		return fmt.Errorf(`malformed request line "%s"`, req)
	}

	method := f[0]
	if !slices.Contains([]string{"M-SEARCH", "NOTIFY"}, method) {
		return fmt.Errorf(`invalid SSDP method "%s"`, method)
	}

	version := f[2]
	if !strings.Contains("HTTP/", version) {
		return fmt.Errorf(`invalid HTTP version "%s"`, version)
	}

	b.requestLine = req
	return nil
}

func (b *upnpBuilder) setMan(man string) {
	if man != "ssdp:discover" {
		fmt.Println(fmt.Errorf(
			`MAN value in SSDP should be "ssdp:discover". 
			Using "%s" instead`, man))
	}
	b.man = man
}

func (b *upnpBuilder) setST(st string) error {
	if !strings.HasPrefix(st, "ssdp:") ||
		!strings.HasPrefix(st, "uuid:") ||
		!strings.HasPrefix(st, "urn:") {
		return fmt.Errorf("invalid ST. Check the UPnP documentation for valid identifiers")
	}

	b.st = st
	return nil
}

// Encode the SSDP message as a string
func (b *upnpBuilder) EncodeToString(host string, port uint16) string {
	h := fmt.Sprintf("%s:%d", host, port)
	return fmt.Sprintf(`
	%s
	HOST: %s
	MAN: "%s"
	ST: %s
	USER-AGENT: %s

	`, b.requestLine, h, b.man, b.st, b.userAgent)
}
