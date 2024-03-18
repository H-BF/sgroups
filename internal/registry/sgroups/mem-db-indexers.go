package sgroups

import (
	"bytes"
	"fmt"
	"math/big"
	"net"
	"reflect"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/c-robinson/iplib"

	"github.com/pkg/errors"
)

type (
	// IPNetIndexer indexer
	IPNetIndexer struct {
		DataAccessor func(obj interface{}) interface{}
	}

	// SingleObjectIndexer -
	SingleObjectIndexer[T any] struct {
		accessor           func(any) T
		fromObjectDelegate func(T) (bool, []byte, error)
	}

	// SGRuleIdIndexer indexer
	SGRuleIdIndexer struct{} //nolint:revive

	// FQDNRuleIdIndexer indexer
	FQDNRuleIdIndexer struct{} //nolint:revive

	// SgIcmpIdIndexer -
	SgIcmpIdIndexer struct{}

	// SgSgIcmpIdIndexer -
	SgSgIcmpIdIndexer struct{}
)

// FromObject impl Indexer
func (idx IPNetIndexer) FromObject(obj interface{}) (bool, []byte, error) {
	if idx.DataAccessor == nil {
		return false, nil, nil
	}
	data := idx.DataAccessor(obj)
	val, err := idx.FromArgs(data)
	return len(val) != 0, val, err
}

// FromArgs impl Indexer
func (idx IPNetIndexer) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, errors.New("must provide only a single argument")
	}
	b := bytes.NewBuffer(nil)
	arg := reflect.Indirect(reflect.ValueOf(args[0])).Interface()
	switch a := arg.(type) {
	case string:
		_, addr, e := net.ParseCIDR(a)
		if e != nil {
			return nil, e
		}
		_, _ = fmt.Fprintf(b, "%s\x00", addr.String())
	case net.IPNet:
		_, _ = fmt.Fprintf(b, "%s\x00", a.String())
	default:
		return nil, errors.New("IPNetIndexer: unsupported data type")
	}
	return b.Bytes(), nil
}

// FromObject impl Indexer
func (idx SGRuleIdIndexer) FromObject(obj interface{}) (bool, []byte, error) {
	val, err := idx.FromArgs(obj)
	return len(val) != 0, val, err
}

// FromArgs impl Indexer
func (idx SGRuleIdIndexer) FromArgs(args ...interface{}) ([]byte, error) { //nolint:dupl
	if len(args) != 1 {
		return nil, errors.New("must provide only a single argument")
	}
	b := bytes.NewBuffer(nil)
	arg := reflect.Indirect(reflect.ValueOf(args[0])).Interface()
	switch a := arg.(type) {
	case model.SGRule:
		_, _ = fmt.Fprintf(b, "%s\x00", a.ID.IdentityHash())
	case model.SGRuleIdentity:
		_, _ = fmt.Fprintf(b, "%s\x00", a.IdentityHash())
	default:
		return nil, errors.New("IPNetIndexer: unsupported data type")
	}
	return b.Bytes(), nil
}

// FromObject impl Indexer
func (idx FQDNRuleIdIndexer) FromObject(obj interface{}) (bool, []byte, error) {
	val, err := idx.FromArgs(obj)
	return len(val) != 0, val, err
}

// FromArgs impl Indexer
func (idx FQDNRuleIdIndexer) FromArgs(args ...interface{}) ([]byte, error) { //nolint:dupl
	if len(args) != 1 {
		return nil, errors.New("must provide only a single argument")
	}
	b := bytes.NewBuffer(nil)
	arg := reflect.Indirect(reflect.ValueOf(args[0])).Interface()
	switch a := arg.(type) {
	case model.FQDNRule:
		_, _ = fmt.Fprintf(b, "%s\x00", a.ID.IdentityHash())
	case model.FQDNRuleIdentity:
		_, _ = fmt.Fprintf(b, "%s\x00", a.IdentityHash())
	default:
		return nil, errors.New("IPNetIndexer: unsupported data type")
	}
	return b.Bytes(), nil
}

// FromObject impl Indexer
func (idx SgIcmpIdIndexer) FromObject(obj interface{}) (bool, []byte, error) {
	val, err := idx.FromArgs(obj)
	return len(val) != 0, val, err
}

// FromArgs impl Indexer
func (idx SgIcmpIdIndexer) FromArgs(args ...interface{}) ([]byte, error) { //nolint:dupl
	if len(args) != 1 {
		return nil, errors.New("must provide only a single argument")
	}
	b := bytes.NewBuffer(nil)
	arg := reflect.Indirect(reflect.ValueOf(args[0])).Interface()
	switch a := arg.(type) {
	case model.SgIcmpRule:
		_, _ = fmt.Fprintf(b, "%s\x00", a.ID().IdentityHash())
	default:
		return nil, errors.New("SgIcmpIdIndexer: unsupported data type")
	}
	return b.Bytes(), nil
}

// FromObject impl Indexer
func (idx SgSgIcmpIdIndexer) FromObject(obj interface{}) (bool, []byte, error) {
	val, err := idx.FromArgs(obj)
	return len(val) != 0, val, err
}

// FromArgs impl Indexer
func (idx SgSgIcmpIdIndexer) FromArgs(args ...interface{}) ([]byte, error) { //nolint:dupl
	if len(args) != 1 {
		return nil, errors.New("must provide only a single argument")
	}
	b := bytes.NewBuffer(nil)
	arg := reflect.Indirect(reflect.ValueOf(args[0])).Interface()
	switch a := arg.(type) {
	case model.SgSgIcmpRule:
		_, _ = fmt.Fprintf(b, "%s\x00", a.ID().IdentityHash())
	default:
		return nil, errors.New("SgSgIcmpIdIndexer: unsupported data type")
	}
	return b.Bytes(), nil
}

// FromObject -
func (idx SingleObjectIndexer[T]) FromObject(obj any) (bool, []byte, error) {
	if idx.accessor == nil {
		panic(
			errors.New("must provide 'accessor'"),
		)
	}
	if idx.fromObjectDelegate == nil {
		panic(
			errors.New("must provide 'fromObjectDelegate'"),
		)
	}
	o := idx.accessor(obj)
	return idx.fromObjectDelegate(o)
}

// FromArgs -
func (idx SingleObjectIndexer[T]) FromArgs(args ...any) ([]byte, error) { //nolint:dupl
	if len(args) != 1 {
		panic(
			errors.New("must provide only a single argument"),
		)
	}
	_, b, e := idx.FromObject(args[0])
	return b, e
}

func (idx SingleObjectIndexer[T]) overrideFromObjectDelegate(f func(T) (bool, []byte, error)) SingleObjectIndexer[T] {
	idx.fromObjectDelegate = f
	return idx
}

type bigInt struct {
	big.Int
}

type cidr2bigInt struct {
	ones   int
	netObj iplib.Net
}

// Cmp -
func (b bigInt) Cmp(other bigInt) int {
	return b.Int.Cmp(&other.Int)
}

func (c *cidr2bigInt) init(CIDR net.IPNet) {
	c.ones, _ = CIDR.Mask.Size()
	c.netObj = iplib.NewNet(CIDR.IP, c.ones)
}

func (c cidr2bigInt) lowerBound() bigInt {
	var ret bigInt
	ip := c.netObj.IP()
	ret.SetBytes(
		ip.To16(),
	)
	return ret
}

func (c cidr2bigInt) upperBound() bigInt {
	var ret bigInt
	ip := c.netObj.LastAddress()
	switch c.netObj.Version() {
	case iplib.IP4Version:
		if c.ones < 31 { //nolint:gomnd
			ip = iplib.NextIP(ip)
		}
	case iplib.IP6Version:
		if c.ones < 128 { //nolint:gomnd
			ip = iplib.NextIP(ip)
		}
	}
	ret.SetBytes(ip.To16())
	return ret
}
