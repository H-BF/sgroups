package sgroups

import (
	"context"
	"strings"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/hashicorp/go-memdb"
	"github.com/pkg/errors"
)

type sGroupsMemDbReader struct {
	reader MemDbReader
}

type syncStatus struct {
	ID int
	model.SyncStatus
}

func isInvalidTableErr(e error) bool {
	if e == nil {
		return false
	}
	return strings.Contains(e.Error(), "invalid table")
}

// GetSyncStatus impl Reader
func (rd sGroupsMemDbReader) GetSyncStatus(_ context.Context) (*model.SyncStatus, error) {
	raw, err := rd.reader.First(TblSyncStatus, indexID)
	if err != nil {
		if isInvalidTableErr(err) {
			return nil, nil
		}
		return nil, err
	}
	switch v := raw.(type) {
	case syncStatus:
		ret := v.SyncStatus
		return &ret, nil
	case nil:
		return nil, nil
	}
	panic("UB")
}

// ListNetworks impl Reader
func (rd sGroupsMemDbReader) ListNetworks(_ context.Context, consume func(model.Network) error, scope Scope) error {
	return memDbListObjects(rd.reader, scope, TblNetworks, consume)
}

// ListSecurityGroups impl Reader
func (rd sGroupsMemDbReader) ListSecurityGroups(_ context.Context, consume func(model.SecurityGroup) error, scope Scope) error {
	var f filterTree[model.SecurityGroup]
	if !f.init(scope) {
		return errors.New("bad scope for 'SecurityGroup' is passed")
	}
	return memDbListObjects(rd.reader, NoScope, TblSecGroups, func(sg model.SecurityGroup) error {
		if e := rd.fillSG(&sg); e != nil {
			return errors.WithMessagef(e, "when fill SG '%s'", sg.Name)
		}
		if !f.invoke(sg) {
			return nil
		}
		return consume(sg)
	})
}

// ListSGRules impl Reader
func (rd sGroupsMemDbReader) ListSGRules(_ context.Context, consume func(model.SGRule) error, scope Scope) error {
	return memDbListObjects(rd.reader, scope, TblSecRules, consume)
}

// ListFqdnRules impl Reader
func (rd sGroupsMemDbReader) ListFqdnRules(_ context.Context, consume func(model.FQDNRule) error, scope Scope) error {
	return memDbListObjects(rd.reader, scope, TblFqdnRules, consume)
}

// ListSgIcmpRules impl Reader
func (rd sGroupsMemDbReader) ListSgIcmpRules(_ context.Context, consume func(model.SgIcmpRule) error, scope Scope) error {
	return memDbListObjects(rd.reader, scope, TblSgIcmpRules, consume)
}

// ListSgSgIcmpRules impl Reader
func (rd sGroupsMemDbReader) ListSgSgIcmpRules(_ context.Context, consume func(model.SgSgIcmpRule) error, scope Scope) error {
	return memDbListObjects(rd.reader, scope, TblSgSgIcmpRules, consume)
}

// ListCidrSgRules impl Reader
func (rd sGroupsMemDbReader) ListCidrSgRules(ctx context.Context, consume func(model.IECidrSgRule) error, scope Scope) error {
	return memDbListObjects(rd.reader, scope, TblCidrSgRules, consume)
}

// ListCidrSgIcmpRules impl Reader
func (rd sGroupsMemDbReader) ListCidrSgIcmpRules(ctx context.Context, consume func(model.IECidrSgIcmpRule) error, scope Scope) error {
	return memDbListObjects(rd.reader, scope, TblIECidrSgIcmpRules, consume)
}

// ListSgSgRules impl Reader
func (rd sGroupsMemDbReader) ListSgSgRules(_ context.Context, consume func(model.IESgSgRule) error, scope Scope) error {
	return memDbListObjects(rd.reader, scope, TblSgSgRules, consume)
}

// ListIESgSgIcmpRules impl Reader interface
func (rd sGroupsMemDbReader) ListIESgSgIcmpRules(_ context.Context, consume func(rule model.IESgSgIcmpRule) error, scope Scope) error {
	return memDbListObjects(rd.reader, scope, TblIESgSgIcmpRules, consume)
}

// Close impl Reader
func (rd sGroupsMemDbReader) Close() error {
	return nil
}

func (rd sGroupsMemDbReader) fillSG(sg *model.SecurityGroup) error {
	nw := sg.Networks[:0]
	seen := make(map[model.NetworkName]bool)
	for _, nwName := range sg.Networks {
		if seen[nwName] {
			continue
		}
		seen[nwName] = true
		x, e := rd.reader.First(TblNetworks, indexID, nwName)
		if e != nil {
			return errors.WithMessage(e, "db error")
		}
		if x != nil {
			nw = append(nw, x.(*model.Network).Name)
		}
	}
	sg.Networks = nw
	return nil
}

func memDbListObjects[T filterKindArg](reader MemDbReader, sc Scope, tbl TableID, consume func(T) error) error {
	var f filterTree[T]
	if !f.init(sc) {
		var t T
		return errors.Errorf("bad scope for '%T' is passed", t)
	}
	it, err := reader.Get(tbl, indexID)
	if err != nil {
		return err
	}
	if it == nil {
		return nil
	}
	it = memdb.NewFilterIterator(it, func(x interface{}) bool {
		return !f.invoke(*x.(*T))
	})
	for x := it.Next(); x != nil; x = it.Next() {
		if e := consume(*x.(*T)); e != nil {
			return e
		}
	}
	return nil
}
