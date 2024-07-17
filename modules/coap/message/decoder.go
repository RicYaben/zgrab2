package message

import (
	"bytes"
	"errors"
)

const (
	OptionBlock1        = 27 // CoAP Block1 Option Number
	OptionBlock2        = 23 // CoAP Block2 Option Number
	OptionContentFormat = 12 // CoAP Content-Format Option Number
)

var (
	ErrMalformedMessage = errors.New("malformed message")
	ErrInvalidValue     = errors.New("invalid value")
	ErrSmallBuffer      = errors.New("buffer too small")
)

type Decoder interface {
	Decode([]byte, *Message) error
}

type decoder struct{}

func NewDecoder() Decoder {
	return &decoder{}
}

func (d *decoder) Decode(data []byte, msg *Message) error {
	var buf = new(bytes.Buffer)
	buf.Write(data)

	var header = new(Header)
	if err := header.Unmarshal(buf); err != nil {
		return err
	}
	msg.Header = header

	var opts = make(Options)
	if err := opts.Unmarshal(buf); err != nil {
		return err
	}
	msg.Options = opts

	var payload = new(Payload)
	cType := uint16(opts[OptionContentFormat].Value[0])
	if err := payload.Unmarshal(buf, cType); err != nil {
		return err
	}
	msg.Payload = payload

	for _, oID := range []uint16{OptionBlock1, OptionBlock2} {
		if opt, ok := opts[oID]; ok {
			msg.block = d.makeBlock(opt)
			break
		}
	}

	return nil
}

func (d *decoder) makeBlock(opt *Option) *Block {
	v := int(opt.Value[0])
	return &Block{
		Number: v >> 4,
		More:   v&0x08 > 0,
	}
}
