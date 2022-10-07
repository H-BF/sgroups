package sgroups

//TableID memory table ID
type TableID int

const (
	//TblNetworks table 'networks'
	TblNetworks TableID = iota

	//TblSecGroups table 'security groups'
	TblSecGroups

	//TblSecRules table 'security rules'
	TblSecRules
)

//SchemaName database scheme name
const SchemaName = "sgroups"

//String stringer interface impl
func (tid TableID) String() string {
	return [...]string{"tbl_network", "tbl_sg", "tbl_rule"}[tid]
}

func (tid TableID) memDbSchema() MemDbSchemaInit {
	return [...]MemDbSchemaInit{
		memDbNetworksSchema,
		memDbSecGroupsSchema,
		memDbSgRulesSchema}[tid]
}

func (TableID) privateMemDbOption() {}
