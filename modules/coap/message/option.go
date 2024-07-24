package message

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

/*
   +-----+----+---+---+---+----------------+--------+--------+---------+
   | No. | C  | U | N | R | Name           | Format | Length | Default |
   +-----+----+---+---+---+----------------+--------+--------+---------+
   |   1 | x  |   |   | x | If-Match       | opaque | 0-8    | (none)  |
   |   3 | x  | x | - |   | Uri-Host       | string | 1-255  | (see    |
   |     |    |   |   |   |                |        |        | below)  |
   |   4 |    |   |   | x | ETag           | opaque | 1-8    | (none)  |
   |   5 | x  |   |   |   | If-None-Match  | empty  | 0      | (none)  |
   |   7 | x  | x | - |   | Uri-Port       | uint   | 0-2    | (see    |
   |     |    |   |   |   |                |        |        | below)  |
   |   8 |    |   |   | x | Location-Path  | string | 0-255  | (none)  |
   |  11 | x  | x | - | x | Uri-Path       | string | 0-255  | (none)  |
   |  12 |    |   |   |   | Content-Format | uint   | 0-2    | (none)  |
   |  14 |    | x | - |   | Max-Age        | uint   | 0-4    | 60      |
   |  15 | x  | x | - | x | Uri-Query      | string | 0-255  | (none)  |
   |  17 | x  |   |   |   | Accept         | uint   | 0-2    | (none)  |
   |  20 |    |   |   | x | Location-Query | string | 0-255  | (none)  |
   |  23 | x  | x | - | - | Block2         | uint   | 0-3    | (none)  |
   |  27 | x  | x | - | - | Block1         | uint   | 0-3    | (none)  |
   |  28 |    |   | x |   | Size2          | uint   | 0-4    | (none)  |
   |  35 | x  | x | - |   | Proxy-Uri      | string | 1-1034 | (none)  |
   |  39 | x  | x | - |   | Proxy-Scheme   | string | 1-255  | (none)  |
   |  60 |    |   | x |   | Size1          | uint   | 0-4    | (none)  |
   +-----+----+---+---+---+----------------+--------+--------+---------+
   C=Critical, U=Unsafe, N=NoCacheKey, R=Repeatable
*/

type ValueFormat uint8

const (
	ValueUnknown ValueFormat = iota
	ValueEmpty
	ValueOpaque
	ValueUint
	ValueString
)

type OptDef struct {
	Name        string
	MinLen      uint16
	MaxLen      uint16
	ValueFormat ValueFormat
}

type Option struct {
	ID    uint16
	Name  string
	Value []byte
}

func (o *Option) UnmarshalValue(data []byte, id uint16) error {
	if def, ok := optionDefinitions[id]; ok {
		o.Name = def.Name

		if def.ValueFormat == ValueUnknown {
			// Skip unrecognized options (RFC7252 section 5.4.1)
			return nil
		}
		if uint16(len(data)) < def.MinLen || uint16(len(data)) > def.MaxLen {
			// Skip options with illegal value length (RFC7252 section 5.4.3)
			return ErrInvalidValue
		}
	}
	o.ID = id
	o.Value = data
	return nil
}

var optionDefinitions = map[uint16]OptDef{
	1:  {"If-Match", 0, 8, ValueOpaque},
	3:  {"Uri-Host", 1, 255, ValueString},
	4:  {"ETag", 1, 8, ValueOpaque},
	5:  {"If-None-Match", 0, 0, ValueEmpty},
	7:  {"Uri-Port", 0, 2, ValueUint},
	8:  {"Location-Path", 0, 255, ValueString},
	11: {"Uri-Path", 0, 255, ValueString},
	12: {"Content-Format", 0, 2, ValueUint},
	14: {"Max-Age", 0, 4, ValueUint},
	15: {"Uri-Query", 0, 255, ValueString},
	17: {"Accept", 0, 2, ValueUint},
	20: {"Location-Query", 0, 255, ValueString},
	23: {"Block2", 0, 3, ValueUint},
	27: {"Block1", 0, 3, ValueUint},
	28: {"Size2", 0, 4, ValueUint},
	35: {"Proxy-Uri", 1, 1034, ValueString},
	39: {"Proxy-Scheme", 1, 255, ValueString},
	60: {"Size1", 0, 4, ValueUint},
}

type Options map[uint16]*Option

func (o *Options) Unmarshal(buf *bytes.Buffer) error {
	prevOpt := 0
	for buf.Len() > 0 {
		b, err := buf.ReadByte()
		if err == io.EOF {
			return err
		}

		delta, length := int(b>>4), int(b&0x0F)
		if delta == 0x0F && length == 0x0F {
			return fmt.Errorf("invalid delta")
		}

		delta, err = o.parseExtOpt(buf, delta)
		if err != nil {
			return err
		}

		length, err = o.parseExtOpt(buf, length)
		if err != nil {
			return err
		}

		if buf.Len() < length {
			return ErrSmallBuffer
		}
		data := buf.Next(length)
		optID := prevOpt + delta

		op := new(Option)
		if err := op.UnmarshalValue(data, uint16(optID)); err == nil {
			(*o)[uint16(optID)] = op
		}
		prevOpt = optID
	}
	return nil
}

func (o *Options) parseExtOpt(buf *bytes.Buffer, v int) (int, error) {
	switch v {
	case 13:
		if buf.Len() < 1 {
			return -1, errors.New("truncated")
		}
		b := buf.Next(1)
		v = int(b[0]) + 13
	case 14:
		if buf.Len() < 2 {
			return -1, errors.New("truncated")
		}
		b := buf.Next(2)
		v = int(binary.BigEndian.Uint16(b)) + 269
	}
	return v, nil
}
