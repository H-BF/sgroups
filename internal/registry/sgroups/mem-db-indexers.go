package sgroups

import (
	"bytes"
	"fmt"
	"net"
	"reflect"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/pkg/errors"
)

type (
	//IPNetIndexer indexer
	IPNetIndexer struct {
		DataAccessor func(obj interface{}) interface{}
	}

	//SGRuleIdIndexer indexer
	SGRuleIdIndexer struct{} //nolint:revive
)

//FromObject impl Indexer
func (idx IPNetIndexer) FromObject(obj interface{}) (bool, []byte, error) {
	if idx.DataAccessor == nil {
		return false, nil, nil
	}
	data := idx.DataAccessor(obj)
	val, err := idx.FromArgs(data)
	return len(val) != 0, val, err
}

//FromArgs impl Indexer
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

//FromObject impl Indexer
func (idx SGRuleIdIndexer) FromObject(obj interface{}) (bool, []byte, error) {
	val, err := idx.FromArgs(obj)
	return len(val) != 0, val, err
}

//FromArgs impl Indexer
func (idx SGRuleIdIndexer) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, errors.New("must provide only a single argument")
	}
	b := bytes.NewBuffer(nil)
	arg := reflect.Indirect(reflect.ValueOf(args[0])).Interface()
	switch a := arg.(type) {
	case model.SGRule:
		_, _ = fmt.Fprintf(b, "%s\x00", a.IdentityHash())
	case model.SGRuleIdentity:
		_, _ = fmt.Fprintf(b, "%s\x00", a.IdentityHash())
	default:
		return nil, errors.New("IPNetIndexer: unsupported data type")
	}
	return b.Bytes(), nil
}
