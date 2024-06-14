package scan

import "github.com/zmap/zgrab2"

type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags

	Method    string `long:"method" default:"GET" description:"Set HTTP request method type"`
	Endpoint  string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint"`
	UserAgent string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`

	MaxSize      int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request"`
	MaxRedirects int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow"`
	HmacKey      string `long:"hmac-key" description:"Base-64 encoded HMAC secret to create and verify JWT identifiers"`

	RetryHTTPS bool `long:"retry-https" description:"If the initial request fails, reconnect and try with HTTPS."`
	UseHTTPS   bool `long:"use-https" description:"Perform an HTTPS connection on the initial host"`

	CustomHeadersNames     string `long:"custom-headers-names" description:"CSV of custom HTTP headers to send to server"`
	CustomHeadersValues    string `long:"custom-headers-values" description:"CSV of custom HTTP header values to send to server. Should match order of custom-headers-names."`
	CustomHeadersDelimiter string `long:"custom-headers-delimiter" description:"Delimiter for customer header name/value CSVs"`

	RequestBody    string `long:"request-body" description:"HTTP request body to send to server"`
	RequestBodyHex string `long:"request-body-hex" description:"HTTP request body to send to server"`

	ComputeDecodedBodyHashAlgorithm string `long:"compute-decoded-body-hash-algorithm" choice:"sha256" choice:"sha1" description:"Choose algorithm for BodyHash field"`

	RawHeaders bool `long:"raw-headers" description:"Extract raw response up through headers"`
}

// Validate performs any needed validation on the arguments
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns module-specific help
func (flags *Flags) Help() string {
	return ""
}
