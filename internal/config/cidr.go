package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"

	"github.com/pkg/errors"
)

type NetCIDR struct {
	*net.IPNet
}

//func (c NetCIDR) Valid() bool{
//	return c.IPNet.Network()
//}

// String -
func (c NetCIDR) String() string {
	return c.IPNet.String()
}

// MarshalJSON -
func (c NetCIDR) MarshalJSON() ([]byte, error) {
	b := bytes.NewBuffer(nil)
	_, e := fmt.Fprintf(b, "%q", c)
	return b.Bytes(), e
}

// UnmarshalJSON -
func (c *NetCIDR) UnmarshalJSON(b []byte) error {
	b1 := bytes.Trim(b, " ")
	n := len(b1)
	if !(n > 2 && b1[0] == '"' && b1[n-1] == '"') {
		return errors.Errorf("bad CIDR value (%s)", string(b))
	}
	b1 = b1[1 : n-1]
	_, nt, e := net.ParseCIDR(string(b1))
	if e != nil {
		return e
	}
	c.IPNet = nt
	return nil
}

func typeCastNetCIDR(data any) (NetCIDR, error) {
	var ret NetCIDR
	var err error
	switch v := data.(type) {
	case []byte:
		err = json.Unmarshal(v, &ret)
	case string:
		err = json.Unmarshal([]byte(v), &ret)
	case NetCIDR:
		ret = v
	case *NetCIDR:
		ret = *v
	default:
		err = errors.Errorf("unable to cast %#v of type %T to NetCIDR", data, data)
	}
	return ret, err
}

func typeCastNetCIDRSlice(data any) ([]NetCIDR, error) {
	var ret []NetCIDR
	var err error
	switch v := data.(type) {
	case []byte:
		err = json.Unmarshal(v, &ret)
	case string:
		err = json.Unmarshal([]byte(v), &ret)
	case []NetCIDR:
		ret = v
	case *[]NetCIDR:
		ret = *v
	default:
		if b, e := json.Marshal(data); e == nil {
			err = json.Unmarshal(b, &ret)
			if err != nil {
				err = errors.Errorf("unable to cast %#v of type %T to []NetCIDR", data, data)
			}
		}
	}
	return ret, err
}
