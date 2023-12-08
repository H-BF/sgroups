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

	// TblSgIcmpRules table SG-SG:ICMP<4|6> rules
	TblSgSgIcmpRules

	// TblCidrSgRules table l4-proto:[INGRESS|EGRESS]-CIDR-SG rules
	TblCidrSgRules
)

// SchemaName database scheme name
const SchemaName = "sgroups"

// String stringer interface impl
func (tid TableID) String() string {
	return tableID2string[tid]
}

// IntegrityChecks -
func (tid TableID) IntegrityChecks() []IntegrityChecker {
	if f := tableID2IntegrityChecks[tid]; f != nil {
		return f()
	}
	return nil
}

var tableID2string = map[TableID]string{
	TblNetworks:      "tbl_network",
	TblSecGroups:     "tbl_sg",
	TblSecRules:      "tbl_sgrule",
	TblSyncStatus:    "tbl_sync_status",
	TblFqdnRules:     "tbl_fqdnrule",
	TblSgIcmpRules:   "tbl_sg_icmp_rule",
	TblSgSgIcmpRules: "tbl_sg_sg_icmp_rule",
	TblCidrSgRules:   "tbl_cidr_sg_rules",
}

var tableID2IntegrityChecks = map[TableID]func() []IntegrityChecker{
	TblSecGroups: func() (ret []IntegrityChecker) {
		ret = append(ret, IntegrityChecker4SG())
		return ret
	},
	TblNetworks: func() (ret []IntegrityChecker) {
		ret = append(ret, IntegrityChecker4Networks())
		return ret
	},
	TblSecRules: func() (ret []IntegrityChecker) {
		ret = append(ret, IntegrityChecker4SGRules())
		return ret
	},
	TblFqdnRules: func() (ret []IntegrityChecker) {
		ret = append(ret, IntegrityChecker4FqdnRules())
		return ret
	},
	TblSgIcmpRules: func() (ret []IntegrityChecker) {
		ret = append(ret, IntegrityChecker4SgIcmpRules())
		return ret
	},
	TblSgSgIcmpRules: func() (ret []IntegrityChecker) {
		ret = append(ret, IntegrityChecker4SgSgIcmpRules())
		return ret
	},
	TblCidrSgRules: func() (ret []IntegrityChecker) {
		ret = append(ret, IntegrityChecker4CidrSgRules())
		return ret
	},
}
