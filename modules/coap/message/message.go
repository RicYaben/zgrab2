package message

import (
	"bytes"
	"fmt"
)

type Block struct {
	Number int
	More   bool
}

type Header struct {
	MessageID int    `json:"message-id"`
	Version   int    `json:"version"`
	Type      int    `json:"type"`
	TokenLen  int    `json:"token-len"`
	Token     []byte `json:"token"`
	Code      string `json:"code"`
}

func NewHeader() *Header {
	return &Header{
		MessageID: -1,
		Type:      -1,
	}
}

func (h *Header) Unmarshal(buf *bytes.Buffer) error {
	d := make([]byte, 4)
	if _, err := buf.Read(d); err != nil {
		return err
	}

	h.Version = int(d[0] >> 6)
	h.Type = int((d[0] >> 4) & 0x03)
	h.TokenLen = int(d[0] & 0x0F)
	h.Code = h.getCode(d[1])
	h.MessageID = int(d[2])<<8 | int(d[3])
	h.Token = make([]byte, h.TokenLen)
	_, err := buf.Read(h.Token)
	return err
}

func (h *Header) getCode(v byte) string {
	// Extract class and detail from the hex value
	class := int(v >> 5)    // upper 3 bits
	detail := int(v & 0x1F) // lower 5 bits
	return fmt.Sprintf("%d.%02d", class, detail)
}

type Message struct {
	Header  *Header  `json:"header"`
	Payload *Payload `json:"payload"`
	Options Options  `json:"options"`

	block *Block
}

func NewMessage() *Message {
	return &Message{
		Header:  NewHeader(),
		Options: make(Options),
	}
}

func (m *Message) GetBlock() *Block {
	return m.block
}
