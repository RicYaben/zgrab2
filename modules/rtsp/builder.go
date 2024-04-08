package rtsp

import (
	"bytes"
	"errors"
	"fmt"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

type Request struct {
	Method  string
	Url     *url.URL
	Headers textproto.MIMEHeader
}

type Response struct {
	Headers textproto.MIMEHeader
	Status  string
}

func (req *Request) Encode() ([]byte, error) {
	var buf bytes.Buffer

	reqLine := fmt.Sprintf("%s %s RTSP/1.0\r\n", req.Method, req.Url.String())
	if _, err := buf.Write([]byte(reqLine)); err != nil {
		return nil, err
	}

	for key, val := range req.Headers {
		header := fmt.Sprintf("%s: %s\r\n", key, strings.Join(val, ", "))
		if _, err := buf.Write([]byte(header)); err != nil {
			return nil, err
		}
	}

	if _, err := buf.Write([]byte("\r\n")); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Validates the status line
// The expected follows the example: RTSP/1.0 200 OK
func validateStatus(statusLine string) error {
	st := strings.TrimSpace(statusLine)
	statusCodes := strings.SplitN(st, " ", 3)
	if len(statusCodes) != 3 {
		return errors.New("invalid response format")
	}

	// Parse protocol
	proto := statusCodes[0]
	validProtos := []string{"RTSP/1.0", "RTSP/2.0"}
	if !slices.Contains(validProtos, proto) {
		return fmt.Errorf("invalid protocol: %s", proto)
	}

	// Parse status code
	if _, err := strconv.Atoi(statusCodes[1]); err != nil {
		return fmt.Errorf("invalid status code: %v", err)
	}

	// Note: we are not parsing the status string.
	return nil
}
