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
	TblNetworks:      memDbNetworksSchema,
	TblSecGroups:     memDbSecGroupsSchema,
	TblSecRules:      memDbSgRulesSchema,
	TblSyncStatus:    memDbSyncStatusSchema,
	TblFqdnRules:     memDbFqdnRulesSchema,
	TblSgIcmpRules:   memSgIcmpRulesSchema,
	TblSgSgIcmpRules: memSgSgIcmpRulesSchema,
	TblCidrSgRules:   memCidrSgRulesSchema,
	TblSgSgRules:     memSgSgRulesSchema,
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

func memCidrSgRulesSchema(schema *MemDbSchema) {
	tbl := TblCidrSgRules.String()
	schema.Tables[tbl] = &MemDbTableSchema{
		Name: tbl,
		Indexes: map[string]*MemDbIndexSchema{
			indexID: { //nolint:dupl
				Name:   indexID,
				Unique: true,
				Indexer: SingleObjectIndexer[model.CidrSgRuleIdenity]{
					accessor: func(a any) model.CidrSgRuleIdenity {
						switch v := a.(type) {
						case *model.CidrSgRule:
							return v.ID
						case model.CidrSgRuleIdenity:
							return v
						default:
							panic(
								errors.Errorf("unsupported type argument %T", a),
							)
						}
					},
					fromObjectDelegate: func(t model.CidrSgRuleIdenity) (bool, []byte, error) {
						b := bytes.NewBuffer(nil)
						_, e := fmt.Fprintf(b, "%s\x00", t)
						return e == nil, b.Bytes(), e
					},
				},
			},
			indexProtoSgTraffic: {
				Name:    indexProtoSgTraffic,
				Indexer: ProtoSgTrafficIndexer{},
			},
			indexSG: {
				Name: indexSG,
				Indexer: SingleObjectIndexer[string]{
					accessor: func(a any) string {
						switch v := a.(type) {
						case *model.CidrSgRule:
							return v.ID.SG
						case model.CidrSgRuleIdenity:
							return v.SG
						default:
							panic(
								errors.Errorf("unsupported type argument %T", a),
							)
						}
					},
					fromObjectDelegate: func(sg string) (bool, []byte, error) {
						b := bytes.NewBuffer(nil)
						_, _ = fmt.Fprintf(b, "%s\x00", sg)
						return b.Len() > 0, b.Bytes(), nil
					},
				},
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
				Indexer: SingleObjectIndexer[model.SgSgRuleIdentity]{
					accessor: func(a any) model.SgSgRuleIdentity {
						switch v := a.(type) {
						case *model.SgSgRule:
							return v.ID
						case model.SgSgRuleIdentity:
							return v
						default:
							panic(
								errors.Errorf("unsupported type argument %T", a),
							)
						}
					},
					fromObjectDelegate: func(t model.SgSgRuleIdentity) (bool, []byte, error) {
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
