package sgroups

// TableID memory table ID
type TableID int

const (
	// TblNetworks table 'networks'
	TblNetworks TableID = iota

	// TblSecGroups table 'security groups'
	TblSecGroups

	// TblSecRules table 'security rules'
	TblSecRules

	// TblSecRules table 'sync-status'
	TblSyncStatus

	// TblFqdnRules table 'fqdn rules'
	TblFqdnRules

	// TblSgIcmpRules table SG:ICMP<4|6> rules
	TblSgIcmpRules
)

// SchemaName database scheme name
const SchemaName = "sgroups"

// String stringer interface impl
func (tid TableID) String() string {
	return tableID2string[tid]
}

var tableID2string = map[TableID]string{
	TblNetworks:    "tbl_network",
	TblSecGroups:   "tbl_sg",
	TblSecRules:    "tbl_sgrule",
	TblSyncStatus:  "tbl_sync_status",
	TblFqdnRules:   "tbl_fqdnrule",
	TblSgIcmpRules: "tbl_sg_icmp_rule",
}
