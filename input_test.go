package zgrab2

import (
	"net"
	"strings"
	"testing"
)

func TestParseCSVTarget(t *testing.T) {
	parseCIDR := func(s string) *net.IPNet {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			panic(err)
		}
		return ipnet
	}

	parseIP := func(s string) *net.IPNet {
		ip := net.ParseIP(s)
		if ip == nil {
			panic("can't parse IP")
		}
		return &net.IPNet{IP: ip}
	}

	ipnetString := func(ipnet *net.IPNet) string {
		if ipnet == nil {
			return "<nil>"
		} else if ipnet.IP != nil && ipnet.Mask != nil {
			return ipnet.String()
		} else if ipnet.IP != nil {
			return ipnet.IP.String()
		}
		panic("malformed ipnet")
	}

	tests := []struct {
		fields  []string
		ipnet   *net.IPNet
		domain  string
		tag     string
		port    string
		success bool
	}{
		// IP DOMAIN TAG PORT
		{
			fields:  []string{"10.0.0.1", "example.com", "tag", "443"},
			ipnet:   parseIP("10.0.0.1"),
			domain:  "example.com",
			tag:     "tag",
			port:    "443",
			success: true,
		},
		// IP DOMAIN TAG PORT
		{
			fields:  []string{"10.0.0.1", "example.com", "tag"},
			ipnet:   parseIP("10.0.0.1"),
			domain:  "example.com",
			tag:     "tag",
			port:    "",
			success: true,
		},
		// IP DOMAIN TAG
		{
			fields:  []string{"10.0.0.1", "example.com", "tag"},
			ipnet:   parseIP("10.0.0.1"),
			domain:  "example.com",
			tag:     "tag",
			success: true,
		},
		// IP DOMAIN (3 fields)
		{
			fields:  []string{"10.0.0.1", "example.com", ""},
			ipnet:   parseIP("10.0.0.1"),
			domain:  "example.com",
			success: true,
		},
		// IP DOMAIN (2 fields)
		{
			fields:  []string{"10.0.0.1", "example.com"},
			ipnet:   parseIP("10.0.0.1"),
			domain:  "example.com",
			success: true,
		},
		// IP (3 fields)
		{
			fields:  []string{"10.0.0.1", "", ""},
			ipnet:   parseIP("10.0.0.1"),
			success: true,
		},
		// IP (2 fields)
		{
			fields:  []string{"10.0.0.1", ""},
			ipnet:   parseIP("10.0.0.1"),
			success: true,
		},
		// IP (1 fields)
		{
			fields:  []string{"10.0.0.1", ""},
			ipnet:   parseIP("10.0.0.1"),
			success: true,
		},
		// CIDR
		{
			fields:  []string{"10.0.0.1/8", ""},
			ipnet:   parseCIDR("10.0.0.1/8"),
			success: true,
		},

		// DOMAIN (2 fields)
		{
			fields:  []string{"", "example.com"},
			domain:  "example.com",
			success: true,
		},

		// Bare domain
		{
			fields:  []string{"example.com"},
			domain:  "example.com",
			success: true,
		},
		// Error: Empty record (1 field)
		{
			fields:  []string{""},
			success: false,
		},
		// Error: Empty record (no fields)
		{
			fields:  []string{},
			success: false,
		},
		// Error: No address or domain
		{
			fields:  []string{"", "", "tag"},
			success: false,
		},
		// Error: Too many fields
		{
			fields:  []string{"", "", "", ""},
			success: false,
		},
		// Error: IP and domain reversed
		{
			fields:  []string{"example.com", "10.0.0.1"},
			success: false,
		},
	}

	for _, test := range tests {
		ipnet, domain, tag, port, err := ParseCSVTarget(test.fields)
		if (err == nil) != test.success {
			t.Errorf("wrong error status (got err=%v, success should be %v): %q", err, test.success, test.fields)
			return
		}
		if err == nil {
			if ipnetString(ipnet) != ipnetString(test.ipnet) || domain != test.domain || tag != test.tag || port != test.port {
				t.Errorf("wrong result (got %v,%v,%v,%v ; expected %v,%v,%v,%v): %q", ipnetString(ipnet), domain, tag, port, ipnetString(test.ipnet), test.domain, test.tag, test.port, test.fields)
				return
			}
		}
	}
}

func TestGetTargetsCSV(t *testing.T) {
	blocklist := `# Comment
0.0.0.0/8           # RFC1122: "This host on this network"
10.0.0.0/8          # RFC1918: Private-Use
100.64.0.0/10       # RFC6598: Shared Address Space
127.0.0.0/8         # RFC1122: Loopback
169.254.0.0/16      # RFC3927: Link Local
172.16.0.0/12       # RFC1918: Private-Use
192.0.0.0/24        # RFC6890: IETF Protocol Assignments
192.0.2.0/24        # RFC5737: Documentation (TEST-NET-1)
192.88.99.0/24      # RFC3068: 6to4 Relay Anycast

192.168.0.0/16      # RFC1918: Private-Use
198.18.0.0/15       # RFC2544: Benchmarking
198.51.100.0/24     # RFC5737: Documentation (TEST-NET-2)
203.0.113.0/24      # RFC5737: Documentation (TEST-NET-3)
240.0.0.0/4         # RFC1112: Reserved
255.255.255.255/32  # RFC0919: Limited Broadcast
`

	input := `# Comment
11.0.0.1,example.com,tag
 11.0.0.1 ,"example.com"
11.0.0.1
,example.com
example.com
2.2.2.2/30,, tag
11.0.0.1,example.com,tag,443
11.0.0.1,,,443
10.0.0.1,,,445
`
	port := uint(443)
	expected := []ScanTarget{
		ScanTarget{IP: net.ParseIP("11.0.0.1"), Domain: "example.com", Tags: "tag"},
		ScanTarget{IP: net.ParseIP("11.0.0.1"), Domain: "example.com"},
		ScanTarget{IP: net.ParseIP("11.0.0.1")},
		ScanTarget{Domain: "example.com"},
		ScanTarget{Domain: "example.com"},
		ScanTarget{IP: net.ParseIP("2.2.2.0"), Tags: "tag"},
		ScanTarget{IP: net.ParseIP("2.2.2.1"), Tags: "tag"},
		ScanTarget{IP: net.ParseIP("2.2.2.2"), Tags: "tag"},
		ScanTarget{IP: net.ParseIP("2.2.2.3"), Tags: "tag"},
		ScanTarget{IP: net.ParseIP("11.0.0.1"), Domain: "example.com", Tags: "tag", Port: &port},
		ScanTarget{IP: net.ParseIP("11.0.0.1"), Port: &port},
	}

	ch := make(chan ScanTarget, 0)
	go func() {
		err := GetTargetsCSV(strings.NewReader(input), strings.NewReader(blocklist), ch)
		if err != nil {
			t.Errorf("GetTargets error: %v", err)
		}
		close(ch)
	}()
	res := []ScanTarget{}
	for r := range ch {
		res = append(res, r)
	}

	if len(res) != len(expected) {
		t.Errorf("wrong number of results (got %d; expected %d)", len(res), len(expected))
		return
	}
	for i := range expected {
		if res[i].IP.String() != expected[i].IP.String() ||
			res[i].Domain != expected[i].Domain ||
			res[i].Tags != expected[i].Tags {
			t.Errorf("wrong data in ScanTarget %d (got %v; expected %v)", i, res[i], expected[i])
		}
	}
}
