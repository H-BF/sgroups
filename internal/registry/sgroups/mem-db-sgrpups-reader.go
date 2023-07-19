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
	var f filterTree[model.SGRule]
	if !f.init(scope) {
		return errors.New("bad scope for 'SGRule' is passed")
	}
	return memDbListObjects(rd.reader, NoScope, TblSecRules, func(rule model.SGRule) error {
		id := &rule.SGRuleIdentity
		if e := rd.fillSgRuleID(id); e != nil {
			return errors.WithMessagef(e, "when fill SgRule %s", rule.SGRuleIdentity)
		}
		if !f.invoke(rule) {
			return nil
		}
		return consume(rule)
	})
}

// ListSGRules impl Reader
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

func (rd sGroupsMemDbReader) fillSgRuleID(sgID *model.SGRuleIdentity) error {
	for _, s := range []*model.SecurityGroup{&sgID.SgFrom, &sgID.SgTo} {
		obj, e := rd.reader.First(TblSecGroups, indexID, s.Name)
		if e != nil {
			return errors.WithMessagef(e, "when find related SG '%s'", s.Name)
		}
		if obj == nil {
			return errors.Errorf("no related SG '%s'", s.Name)
		}
		*s = *obj.(*model.SecurityGroup)
		if e = rd.fillSG(s); e != nil {
			return errors.WithMessagef(e, "when fill SG '%s'", s.Name)
		}
	}
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
