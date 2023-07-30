package sgroups

import (
	model "github.com/H-BF/sgroups/internal/models/sgroups"
)

func (tid TableID) memDbSchema() MemDbSchemaInit {
	return [...]MemDbSchemaInit{
		memDbNetworksSchema,
		memDbSecGroupsSchema,
		memDbSgRulesSchema,
		memDbSyncStatusSchema}[tid]
}

func (TableID) privateMemDbOption() {}

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
