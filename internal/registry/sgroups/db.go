package sgroups

// TableID memory table ID
type TableID int

const (
	//TblNetworks table 'networks'
	TblNetworks TableID = iota

	//TblSecGroups table 'security groups'
	TblSecGroups

	//TblSecRules table 'security rules'
	TblSecRules

	//TblSecRules table 'sync-status'
	TblSyncStatus
)

// SchemaName database scheme name
const SchemaName = "sgroups"

// String stringer interface impl
func (tid TableID) String() string {
	return [...]string{"tbl_network", "tbl_sg", "tbl_rule", "tbl_sync_status"}[tid]
}
