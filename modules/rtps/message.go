package rtps

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type RTPSMessage struct {
	Header  *RTPSHeader `json:"header"`
	Payload []byte      `json:"payload"`
}

type RTPSHeader struct {
	Magic      [4]byte  // "RTPS"
	Version    [2]byte  `json:"protocol-version"`
	VendorID   [2]byte  `json:"vendor-id"`
	GUIDPrefix [12]byte `json:"guid-prefix"`
}

func (header *RTPSHeader) Unmarshal(buf *bytes.Buffer) error {
	if buf.Len() < 20 {
		return fmt.Errorf("data too short for RTPS header")
	}

	if err := binary.Read(buf, binary.BigEndian, header); err != nil {
		return fmt.Errorf("failed to parse RTPS header: %w", err)
	}

	if header.Magic != [4]byte{'R', 'T', 'P', 'S'} {
		return fmt.Errorf("not RTPS message")
	}

	return nil
}

type rtpsDecoder struct{}

func (d *rtpsDecoder) Decode(data []byte, msg *RTPSMessage) error {
	var buf = new(bytes.Buffer)
	buf.Write(data)

	var header = new(RTPSHeader)
	if err := header.Unmarshal(buf); err != nil {
		return err
	}
	msg.Header = header
	msg.Payload = buf.Bytes()
	return nil
}
