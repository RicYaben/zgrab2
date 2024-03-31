package upnp

import (
	"fmt"

	"golang.org/x/exp/slices"
)

type OptionID uint

const (
	MX OptionID = iota
	ST
)

type optionDef struct {
	options []string
	minVal  int
	maxVal  int
}

var options = [2]optionDef{
	MX: optionDef{minVal: 1, maxVal: 5},
	ST: optionDef{options: []string{"ssdp:all", "upnp:rootdevice"}},
}

type Message struct {
	Header string `json:"header" description:"Header of the packet. This value is fixed to 'M-SEARCH * HTTP/1.1'"`
	MAN    string `json:"man" description:"Scope. This must be 'ssdp:discover'"`
	MX     int    `json:"mx" description:"Maximum wait time in seconds"`
	ST     string `json:"st" description:"Search Target. Options: all, rootdevice"`
}

func (m *Message) Init(mx uint, st string) error {
	m.Header = "M-SEARCH * HTTP/1.1"
	m.MAN = "ssdp:discover"

	// Check the options that we would like to allow
	stOptions := options[ST].options
	if !slices.Contains(stOptions, st) {
		return fmt.Errorf("invalid ST value %s", st)
	}
	m.ST = st

	return nil
}
