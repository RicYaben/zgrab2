package coap

import (
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

type coapTester struct {
	port           int
	expectedStatus zgrab2.ScanStatus
}

func (t *coapTester) getScanner() (*Scanner, error) {
	var module Module
	flags := module.NewFlags().(*Flags)
	flags.Port = uint(t.port)

	flags.Paths = "\".well-known/core\",\"/\""
	flags.PathsDelimiter = ","
	flags.Timeout = 10 * time.Second
	flags.Port = uint(t.port)

	scanner := module.NewScanner()
	if err := scanner.Init(flags); err != nil {
		return nil, err
	}

	return scanner.(*Scanner), nil
}

func (t *coapTester) runTest(test *testing.T, name string) {
	scanner, err := t.getScanner()
	if err != nil {
		test.Fatalf("[%s] Unexpected error: %v", name, err)
	}

	target := zgrab2.ScanTarget{
		Domain: "coap.me",
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

var tests = map[string]*coapTester{
	"success": {
		port:           5683,
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
}

func TestCoAP(t *testing.T) {
	for tname, cfg := range tests {
		cfg.runTest(t, tname)
	}
}
