package config

import (
	"bytes"
	"encoding/json"
	"net"

	"github.com/pkg/errors"
)

// IP -
type IP struct {
	net.IP
}

// String -
func (ip IP) String() string {
	return ip.IP.String()
}

// MarshalJSON -
func (ip IP) MarshalJSON() ([]byte, error) {
	t, e := ip.MarshalText()
	if e != nil {
		return nil, e
	}
	b := bytes.NewBuffer(nil)
	b.WriteByte('"')
	if _, e = b.Write(t); e != nil {
		return nil, e
	}
	b.WriteByte('"')
	return b.Bytes(), e
}

// UnmarshalJSON -
func (ip *IP) UnmarshalJSON(b []byte) error {
	b1 := bytes.Trim(b, " ")
	n := len(b1)
	if !(n >= 2 && b1[0] == '"' && b1[n-1] == '"') {
		return errors.Errorf("bad IP value (%s)", string(b))
	}
	b1 = b1[1 : n-1]
	var p net.IP
	if e := p.UnmarshalText(b1); e != nil {
		return e
	}
	ip.IP = p
	return nil
}

func typeCastIP(data any) (IP, error) {
	var ret IP
	var err error
	switch v := data.(type) {
	case []byte:
		err = json.Unmarshal(v, &ret)
	case string:
		err = json.Unmarshal([]byte(v), &ret)
	case IP:
		ret = v
	case *IP:
		ret = *v
	default:
		err = errors.Errorf("unable to cast %#v of type %T to IP", data, data)
	}
	return ret, err
}

func typeCastIPSlice(data any) ([]IP, error) {
	var ret []IP
	var err error
	switch v := data.(type) {
	case []byte:
		err = json.Unmarshal(v, &ret)
	case string:
		err = json.Unmarshal([]byte(v), &ret)
	case []IP:
		ret = v
	case *[]IP:
		ret = *v
	default:
		if b, e := json.Marshal(data); e == nil {
			err = json.Unmarshal(b, &ret)
			if err != nil {
				err = errors.Errorf("unable to cast %#v of type %T to []IP", data, data)
			}
		}
	}
	return ret, err
}
