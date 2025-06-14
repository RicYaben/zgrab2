package rtps

import (
	"context"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

type rtpsTester struct {
	target         zgrab2.ScanTarget
	expectedStatus zgrab2.ScanStatus
}

func (t *rtpsTester) getScanner() (*Scanner, error) {
	var module Module
	flags := module.NewFlags().(*Flags)
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

	baseFlags := &zgrab2.BaseFlags{
		Port:           t.target.Port,
		ConnectTimeout: time.Second * 10,
		TargetTimeout:  time.Second * 10,
	}

	dialerGroupConfig := zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportUDP,
		BaseFlags:                       baseFlags,
		TLSEnabled:                      false,
	}

	dialerGroup, err := dialerGroupConfig.GetDefaultDialerGroupFromConfig()
	if err != nil {
		test.Fatalf("Error getting default dialer group: %v", err)
	}

	status, ret, err := scanner.Scan(context.Background(), dialerGroup, &t.target)
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
		target: zgrab2.ScanTarget{
			Domain: "coap.me",
			Port:   7400,
		},
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
}

func TestRTPS(t *testing.T) {
	for tname, cfg := range tests {
		cfg.runTest(t, tname)
	}
}
