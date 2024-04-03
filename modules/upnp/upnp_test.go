package upnp

import (
	"fmt"
	"testing"
	"time"
)

type upnpTester struct {
	port     int
	lport    int
	laddress string
}

func (cfg *upnpTester) runFakeUPnPServer(t *testing.T) {
	endpoint := fmt.Sprintf("127.0.0.1")
}

func (cfg *upnpTester) getScanner(t *testing.T) *Scanner {
	var module Module
	flags := module.NewFlags().(*Flags)
	flags.Method = "M-SEARCH"
	flags.Man = "ssdp:discover"
	flags.St = "ssdp:all"
	flags.UserAgent = "Mozilla/5.0 zgrab/0.x"
	flags.Port = uint(cfg.port)
	flags.Timeout = 1 * time.Second
	flags.LocalAddress = cfg.laddress
	flags.LocalPort = uint(cfg.lport)

	scanner := module.NewScanner()
	scanner.Init(flags)
	return scanner.(*Scanner)
}
