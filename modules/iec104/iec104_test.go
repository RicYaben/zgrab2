package iec104

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

type iec104Tester struct {
	target         zgrab2.ScanTarget
	expectedStatus zgrab2.ScanStatus
}

func (t *iec104Tester) getScanner() (*Scanner, error) {
	var module Module
	flags := module.NewFlags().(*Flags)

	flags.UseTLS = false
	flags.RetryTLS = false

	flags.CARanges = "1-2,10,65535"
	flags.CADelimiter = ","
	flags.CASeparator = "-"
	flags.Limit = 10

	scanner := module.NewScanner()
	if err := scanner.Init(flags); err != nil {
		return nil, err
	}

	return scanner.(*Scanner), nil
}

func (t *iec104Tester) runTest(test *testing.T, name string) {
	scanner, err := t.getScanner()
	if err != nil {
		test.Fatalf("[%s] Unexpected error: %v", name, err)
	}

	baseFlags := &zgrab2.BaseFlags{
		Port:           t.target.Port,
		ConnectTimeout: time.Second * 20,
		TargetTimeout:  time.Second * 20,
	}

	dialerGroupConfig := zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,
		BaseFlags:                       baseFlags,
		TLSEnabled:                      scanner.config.UseTLS || scanner.config.RetryTLS,
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

var tests = map[string]*iec104Tester{
	"success": {
		target: zgrab2.ScanTarget{
			IP:   net.ParseIP("<>"),
			Port: 2404,
		},
		expectedStatus: zgrab2.SCAN_SUCCESS,
	},
}

func TestIEC104(t *testing.T) {
	for tname, cfg := range tests {
		cfg.runTest(t, tname)
	}
}
