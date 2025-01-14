package rtps

import (
	"net"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

type rtpsTester struct {
	addr           string
	port           int
	expectedStatus zgrab2.ScanStatus
}

func (t *rtpsTester) getScanner() (*Scanner, error) {
	var module Module
	flags := module.NewFlags().(*Flags)
	flags.Port = uint(t.port)

	flags.Timeout = 20 * time.Second
	flags.Port = uint(t.port)

	scanner := module.NewScanner()
	if err := scanner.Init(flags); err != nil {
		return nil, err
	}

	return scanner.(*Scanner), nil
}

func (t *rtpsTester) runTest(test *testing.T, name string) {
	scanner, err := t.getScanner()
	if err != nil {
		test.Fatalf("[%s] Unexpected error: %v", name, err)
	}

	target := zgrab2.ScanTarget{
		IP: net.ParseIP(t.addr),
	}

	status, ret, err := scanner.Scan(target)
	if status != t.expectedStatus {
		test.Errorf("[%s] Wrong status: expected %s, got %s", name, t.expectedStatus, status)
	}

	if err != nil {
		test.Errorf("[%s] Unexpected error: %v", name, err)
	}

	if ret == nil {
		test.Errorf("[%s] Got empty response", name)
	}
}

var tests = map[string]*rtpsTester{
	"success": {
		addr:           "<ip addr here>",
		port:           7400,
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
}

func TestRTPS(t *testing.T) {
	for tname, cfg := range tests {
		cfg.runTest(t, tname)
	}
}
