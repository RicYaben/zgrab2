package opcua

import (
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

type opcuaTester struct {
	address  string
	port     uint
	uri      string
	certHost string
	endpoint string
	level    uint
}

func (cfg *opcuaTester) getScanner() (*Scanner, error) {
	var module Module
	flags := module.NewFlags().(*Flags)
	flags.Uri = cfg.uri
	flags.CertHost = cfg.certHost
	flags.Endpoint = cfg.endpoint
	flags.BrowseDepth = cfg.level
	flags.Timeout = 30 * time.Second

	scanner := module.NewScanner()
	if err := scanner.Init(flags); err != nil {
		return nil, err
	}
	return scanner.(*Scanner), nil
}

func (cfg *opcuaTester) runTest(t *testing.T, testName string) {
	target := zgrab2.ScanTarget{
		Port:   &cfg.port,
		Domain: cfg.address,
	}

	scanner, err := cfg.getScanner()
	if err != nil {
		t.Fatalf("[%s] Unexpected error: %v", testName, err)
	}

	st, res, err := scanner.Scan(target)
	if err != nil {
		t.Fatalf("[%s] error while scanning: %v, %v", testName, err, st)
	}
	t.Logf("%+v", res)
}

var tests = map[string]*opcuaTester{
	"demo": {
		address:  "opcua.demo-this.com",
		port:     51210,
		uri:      "urn:opcua:scanner",
		certHost: "localhost",
		endpoint: "UADiscovery", //UA/SampleServer
		level:    2,
	},
}

func TestOPCUA(t *testing.T) {
	for tname, cfg := range tests {
		cfg.runTest(t, tname)
	}
}
