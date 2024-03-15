package sgroups

import (
	"bytes"
	"fmt"

	model "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/pkg/errors"
)

func (tid TableID) memDbSchema() MemDbSchemaInit {
	return tableID2MemDbSchemaInit[tid]
}

var tableID2MemDbSchemaInit = map[TableID]MemDbSchemaInit{
	TblNetworks:          memDbNetworksSchema,
	TblSecGroups:         memDbSecGroupsSchema,
	TblSecRules:          memDbSgRulesSchema,
	TblSyncStatus:        memDbSyncStatusSchema,
	TblFqdnRules:         memDbFqdnRulesSchema,
	TblSgIcmpRules:       memSgIcmpRulesSchema,
	TblSgSgIcmpRules:     memSgSgIcmpRulesSchema,
	TblCidrSgRules:       memCidrSgRulesSchema,
	TblSgSgRules:         memSgSgRulesSchema,
	TblIESgSgIcmpRules:   memIESgSgIcmpRulesSchema,
	TblIECidrSgIcmpRules: memCidrSgIcmpRulesSchema,
}

func memDbNetworksSchema(schema *MemDbSchema) {
	tbl := TblNetworks.String()
	schema.Tables[tbl] = &MemDbTableSchema{
		Name: tbl,
		Indexes: map[string]*MemDbIndexSchema{
			indexID: {
				Name:    indexID,
				Unique:  true,
				Indexer: &MemDbStringFieldIndex{Field: "Name"},
			},
			indexIPNet: {
				Name:   indexIPNet,
				Unique: true,
				Indexer: IPNetIndexer{
					DataAccessor: func(obj interface{}) interface{} {
						return obj.(*model.Network).Net
					},
				},
			},
		},
	}
}

func memDbSecGroupsSchema(schema *MemDbSchema) {
	tbl := TblSecGroups.String()
	schema.Tables[tbl] = &MemDbTableSchema{
		Name: tbl,
		Indexes: map[string]*MemDbIndexSchema{
			indexID: {
				Name:    indexID,
				Unique:  true,
				Indexer: &MemDbStringFieldIndex{Field: "Name"},
			},
		},
	}
}

func memDbSgRulesSchema(schema *MemDbSchema) {
	tbl := TblSecRules.String()
	schema.Tables[tbl] = &MemDbTableSchema{
		Name: tbl,
		Indexes: map[string]*MemDbIndexSchema{
			indexID: {
				Name:    indexID,
				Unique:  true,
				Indexer: SGRuleIdIndexer{},
			},
		},
	}
}

func memDbFqdnRulesSchema(schema *MemDbSchema) {
	tbl := TblFqdnRules.String()
	schema.Tables[tbl] = &MemDbTableSchema{
		Name: tbl,
		Indexes: map[string]*MemDbIndexSchema{
			indexID: {
				Name:    indexID,
				Unique:  true,
				Indexer: FQDNRuleIdIndexer{},
			},
		},
	}
}

func memSgIcmpRulesSchema(schema *MemDbSchema) {
	tbl := TblSgIcmpRules.String()
	schema.Tables[tbl] = &MemDbTableSchema{
		Name: tbl,
		Indexes: map[string]*MemDbIndexSchema{
			indexID: {
				Name:    indexID,
				Unique:  true,
				Indexer: SgIcmpIdIndexer{},
			},
		},
	}
}

func memSgSgIcmpRulesSchema(schema *MemDbSchema) {
	tbl := TblSgSgIcmpRules.String()
	schema.Tables[tbl] = &MemDbTableSchema{
		Name: tbl,
		Indexes: map[string]*MemDbIndexSchema{
			indexID: {
				Name:    indexID,
				Unique:  true,
				Indexer: SgSgIcmpIdIndexer{},
			},
		},
	}
}

func memIESgSgIcmpRulesSchema(schema *MemDbSchema) {
	tbl := TblIESgSgIcmpRules.String()
	schema.Tables[tbl] = &MemDbTableSchema{
		Name: tbl,
		Indexes: map[string]*MemDbIndexSchema{
			indexID: {
				Name:   indexID,
				Unique: true,
				Indexer: SingleObjectIndexer[model.IESgSgIcmpRuleID]{
					accessor: func(a any) model.IESgSgIcmpRuleID {
						switch v := a.(type) {
						case *model.IESgSgIcmpRule:
							return v.ID()
						case model.IESgSgIcmpRuleID:
							return v
						default:
							panic(
								errors.Errorf("unsupported type argument %T", a),
							)
						}
					},
					fromObjectDelegate: func(t model.IESgSgIcmpRuleID) (bool, []byte, error) {
						b := bytes.NewBuffer(nil)
						_, e := fmt.Fprintf(b, "%s\x00", t)
						return e == nil, b.Bytes(), e
					},
				},
			},
		},
	}
}

func memCidrSgIcmpRulesSchema(schema *MemDbSchema) {
	tbl := TblIECidrSgIcmpRules.String()

	common := SingleObjectIndexer[model.IECidrSgIcmpRuleID]{
		accessor: func(a any) model.IECidrSgIcmpRuleID {
			switch v := a.(type) {
			case *model.IECidrSgIcmpRule:
				return v.ID()
			case model.IECidrSgIcmpRuleID:
				return v
			default:
				panic(
					errors.Errorf("unsupported type argument %T", a),
				)
			}
		},
	}
	schema.Tables[tbl] = &MemDbTableSchema{
		Name: tbl,
		Indexes: map[string]*MemDbIndexSchema{
			indexID: {
				Name:   indexID,
				Unique: true,
				Indexer: common.overrideFromObjectDelegate(func(t model.IECidrSgIcmpRuleID) (bool, []byte, error) {
					b := bytes.NewBuffer(nil)
					_, e := fmt.Fprintf(b, "%s\x00", t)
					return e == nil, b.Bytes(), e
				}),
			},
			indexIPvSgTraffic: {
				Name: indexIPvSgTraffic,
				Indexer: common.overrideFromObjectDelegate(func(t model.IECidrSgIcmpRuleID) (bool, []byte, error) {
					b := bytes.NewBuffer(nil)
					_, e := fmt.Fprintf(b, "IPv%vsg(%s)%s\x00", t.IPv, t.SG, t.Traffic)
					return e == nil, b.Bytes(), e
				}),
			},
		},
	}
}

func memCidrSgRulesSchema(schema *MemDbSchema) {
	tbl := TblCidrSgRules.String()

	common := SingleObjectIndexer[model.IECidrSgRuleIdenity]{
		accessor: func(a any) model.IECidrSgRuleIdenity {
			switch v := a.(type) {
			case *model.IECidrSgRule:
				return v.ID
			case model.IECidrSgRuleIdenity:
				return v
			default:
				panic(
					errors.Errorf("unsupported type argument %T", a),
				)
			}
		},
	}
	schema.Tables[tbl] = &MemDbTableSchema{
		Name: tbl,
		Indexes: map[string]*MemDbIndexSchema{
			indexID: {
				Name:   indexID,
				Unique: true,
				Indexer: common.overrideFromObjectDelegate(func(t model.IECidrSgRuleIdenity) (bool, []byte, error) {
					b := bytes.NewBuffer(nil)
					_, e := fmt.Fprintf(b, "%s\x00", t)
					return e == nil, b.Bytes(), e
				}),
			},
			indexProtoSgTraffic: {
				Name: indexProtoSgTraffic,
				Indexer: common.overrideFromObjectDelegate(func(o model.IECidrSgRuleIdenity) (bool, []byte, error) {
					b := bytes.NewBuffer(nil)
					_, e := fmt.Fprintf(b, "%s:sg(%s)%s\x00", o.Transport, o.SG, o.Traffic)
					return e == nil, b.Bytes(), e
				}),
			},
			indexSG: {
				Name: indexSG,
				Indexer: common.overrideFromObjectDelegate(func(o model.IECidrSgRuleIdenity) (bool, []byte, error) {
					b := bytes.NewBuffer(nil)
					_, e := fmt.Fprintf(b, "%s\x00", o.SG)
					return e == nil, b.Bytes(), e
				}),
			},
		},
	}
}

func memSgSgRulesSchema(schema *MemDbSchema) {
	tbl := TblSgSgRules.String()
	schema.Tables[tbl] = &MemDbTableSchema{
		Name: tbl,
		Indexes: map[string]*MemDbIndexSchema{
			indexID: { //nolint:dupl
				Name:   indexID,
				Unique: true,
				Indexer: SingleObjectIndexer[model.IESgSgRuleIdentity]{
					accessor: func(a any) model.IESgSgRuleIdentity {
						switch v := a.(type) {
						case *model.IESgSgRule:
							return v.ID
						case model.IESgSgRuleIdentity:
							return v
						default:
							panic(
								errors.Errorf("unsupported type argument %T", a),
							)
						}
					},
					fromObjectDelegate: func(t model.IESgSgRuleIdentity) (bool, []byte, error) {
						b := bytes.NewBuffer(nil)
						_, e := fmt.Fprintf(b, "%s\x00", t)
						return e == nil, b.Bytes(), e
					},
				},
			},
		},
	}
}

func memDbSyncStatusSchema(schema *MemDbSchema) {
	tbl := TblSyncStatus.String()
	schema.Tables[tbl] = &MemDbTableSchema{
		Name: tbl,
		Indexes: map[string]*MemDbIndexSchema{
			indexID: {
				Name:    indexID,
				Unique:  true,
				Indexer: &MemDbStringFieldIndex{Field: "ID"},
			},
		},
	}
}
