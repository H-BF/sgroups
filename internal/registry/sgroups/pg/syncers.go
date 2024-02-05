package pg

import (
	"bytes"
	"context"
	"io"
	"sync"

	sgm "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/jackc/pgx/v5"
	"github.com/pkg/errors"
)

// SyncerOfNetworks -
type SyncerOfNetworks = syncObj[sgm.Network, string]

// SyncerOfSecGroups -
type SyncerOfSecGroups = syncObj[sgm.SecurityGroup, string]

// SyncerOfSgRules -
type SyncerOfSgRules = syncObj[sgm.SGRule, sgm.SGRuleIdentity]

// SyncerOfSg2FqdnRules -
type SyncerOfSg2FqdnRules = syncObj[sgm.FQDNRule, sgm.FQDNRuleIdentity]

// SyncerOfSgIcmpRules -
type SyncerOfSgIcmpRules = syncObj[sgm.SgIcmpRule, sgm.SgIcmpRuleID]

// SyncerOfSgIcmpRules -
type SyncerOfSgSgIcmpRules = syncObj[sgm.SgSgIcmpRule, sgm.SgSgIcmpRuleID]

type SyncerOfCidrSgRules = syncObj[sgm.CidrSgRule, sgm.CidrSgRuleIdenity]

type SyncerOfSgSgRules = syncObj[sgm.SgSgRule, sgm.SgSgRuleIdentity]

type syncObj[T any, tFlt any] struct {
	C   *pgx.Conn
	Ins bool
	Upd bool
	Del bool

	ensureConstructed sync.Once
	syncGenSQL
	flt struct {
		sync.Once
		*syncTable
		err error
	}
	src struct {
		syncTable
		sync.Once
		err error
	}
}

func (o *syncObj[T, tFlt]) construct() {
	switch any((*T)(nil)).(type) {
	case *sgm.Network:
		o.tableDst = syncTable{
			Name: "sgroups.tbl_network",
		}.WithFields(
			syncField{Name: "name", PgTy: "sgroups.cname", Notnull: true, Pk: true},
			syncField{Name: "network", PgTy: "cidr", Notnull: true},
		)
		o.mutatorFn = "sgroups.sync_network"
	case *sgm.SecurityGroup:
		o.tableDst = syncTable{
			Name: "sgroups.vu_sg",
		}.WithFields(
			syncField{Name: "name", PgTy: "sgroups.cname", Notnull: true, Pk: true},
			syncField{Name: "networks", PgTy: "sgroups.cname[]"},
			syncField{Name: "logs", PgTy: "bool", Notnull: true},
			syncField{Name: "trace", PgTy: "bool", Notnull: true},
			syncField{Name: "default_action", PgTy: "sgroups.chain_default_action", Notnull: true},
		)
		o.mutatorFn = "sgroups.sync_sg"
	case *sgm.SGRule:
		o.tableDst = syncTable{
			Name: "sgroups.vu_sg_rule",
		}.WithFields(
			syncField{Name: "sg_from", PgTy: "sgroups.cname", Notnull: true, Pk: true},
			syncField{Name: "sg_to", PgTy: "sgroups.cname", Notnull: true, Pk: true},
			syncField{Name: "proto", PgTy: "sgroups.proto", Notnull: true, Pk: true},
			syncField{Name: "ports", PgTy: "sgroups.sg_rule_ports[]"},
			syncField{Name: "logs", PgTy: "bool", Notnull: true},
		)
		o.mutatorFn = "sgroups.sync_sg_rule"
	case *sgm.FQDNRule:
		o.tableDst = syncTable{
			Name: "sgroups.vu_fqdn_rule",
		}.WithFields(
			syncField{Name: "sg_from", PgTy: "sgroups.cname", Notnull: true, Pk: true},
			syncField{Name: "fqdn_to", PgTy: "sgroups.fqdn", Notnull: true, Pk: true},
			syncField{Name: "proto", PgTy: "sgroups.proto", Notnull: true, Pk: true},
			syncField{Name: "ports", PgTy: "sgroups.sg_rule_ports[]"},
			syncField{Name: "logs", PgTy: "bool", Notnull: true},
			syncField{Name: "ndpi_protocols", PgTy: "citext[]", Notnull: true},
		)
		o.mutatorFn = "sgroups.sync_fqdn_rule"
	case *sgm.SgIcmpRule:
		o.mutatorFn = "sgroups.sync_sg_icmp_rule"
		o.tableDst = syncTable{
			Name: "sgroups.vu_sg_icmp_rule",
		}.WithFields(
			syncField{Name: "ip_v", PgTy: "sgroups.ip_family", Notnull: true, Pk: true},
			syncField{Name: "sg", PgTy: "sgroups.cname", Notnull: true, Pk: true},
			syncField{Name: "types", PgTy: "sgroups.icmp_types", Notnull: true},
			syncField{Name: "logs", PgTy: "bool", Notnull: true},
			syncField{Name: "trace", PgTy: "bool", Notnull: true},
		)
	case *sgm.SgSgIcmpRule:
		o.mutatorFn = "sgroups.sync_sg_sg_icmp_rule"
		o.tableDst = syncTable{
			Name: "sgroups.vu_sg_sg_icmp_rule",
		}.WithFields(
			syncField{Name: "ip_v", PgTy: "sgroups.ip_family", Notnull: true, Pk: true},
			syncField{Name: "sg_from", PgTy: "sgroups.cname", Notnull: true, Pk: true},
			syncField{Name: "sg_to", PgTy: "sgroups.cname", Notnull: true, Pk: true},
			syncField{Name: "types", PgTy: "sgroups.icmp_types", Notnull: true},
			syncField{Name: "logs", PgTy: "bool", Notnull: true},
			syncField{Name: "trace", PgTy: "bool", Notnull: true},
		)
	case *sgm.CidrSgRule:
		o.mutatorFn = "sgroups.sync_cidr_sg_rule"
		o.tableDst = syncTable{
			Name: "sgroups.vu_cidr_sg_rule",
		}.WithFields(
			syncField{Name: "proto", PgTy: "sgroups.proto", Notnull: true, Pk: true},
			syncField{Name: "cidr", PgTy: "cidr", Notnull: true, Pk: true},
			syncField{Name: "sg", PgTy: "sgroups.cname", Notnull: true, Pk: true},
			syncField{Name: "traffic", PgTy: "sgroups.traffic", Notnull: true, Pk: true},
			syncField{Name: "ports", PgTy: "sgroups.sg_rule_ports[]"},
			syncField{Name: "logs", PgTy: "bool", Notnull: true},
			syncField{Name: "trace", PgTy: "bool", Notnull: true},
		)
	case *sgm.SgSgRule:
		o.mutatorFn = "sgroups.sync_ie_sg_sg_rule"
		o.tableDst = syncTable{
			Name: "sgroups.vu_ie_sg_sg_rule",
		}.WithFields(
			syncField{Name: "proto", PgTy: "sgroups.proto", Notnull: true, Pk: true},
			syncField{Name: "sg_local", PgTy: "sgroups.cname", Notnull: true, Pk: true},
			syncField{Name: "sg", PgTy: "sgroups.cname", Notnull: true, Pk: true},
			syncField{Name: "traffic", PgTy: "sgroups.traffic", Notnull: true, Pk: true},
			syncField{Name: "ports", PgTy: "sgroups.sg_rule_ports[]"},
			syncField{Name: "logs", PgTy: "bool", Notnull: true},
			syncField{Name: "trace", PgTy: "bool", Notnull: true},
		)
	default:
		panic("UB")
	}
}

func (o *syncObj[T, tFlt]) enureFilterTable(ctx context.Context) error {
	o.flt.Do(func() {
		x := syncTable{
			Temporary: true,
			OnCommit:  "drop",
		}.WithRandomName("flt_", "")
		for _, f := range o.tableDst.fields {
			if f.Pk {
				x.fields = append(x.fields, f)
			}
		}
		o.flt.syncTable = &x
		o.flt.err = x.Create(ctx, o.C)
	})
	return o.flt.err
}

func (o *syncObj[T, tFlt]) enureDataTable(ctx context.Context) error {
	o.src.Do(func() {
		x := o.tableDst.WithRandomName("data_", "")
		x.Temporary = true
		x.OnCommit = "drop"
		o.src.syncTable = x
		o.dataTable = x.Name
		o.src.err = x.Create(ctx, o.C)
	})
	return o.src.err
}

// AddToFilter -
func (o *syncObj[T, tFlt]) AddToFilter(ctx context.Context, data ...tFlt) error {
	o.ensureConstructed.Do(o.construct)
	var raw RawRowsData
	if err := o.enureFilterTable(ctx); err != nil {
		return err
	}
	for _, d := range data {
		switch v := any(d).(type) {
		case string:
			raw = append(raw, []any{v})
		case sgm.FQDNRuleIdentity:
			var p Proto
			if err := p.FromModel(v.Transport); err != nil {
				return err
			}
			raw = append(raw, []any{v.SgFrom, v.FqdnTo, p})
		case sgm.SGRuleIdentity:
			var p Proto
			if err := p.FromModel(v.Transport); err != nil {
				return err
			}
			raw = append(raw, []any{v.SgFrom, v.SgTo, p})
		case sgm.SgIcmpRuleID:
			ipv, e := ipFamilyFromModel(v.IPv)
			if e != nil {
				return e
			}
			raw = append(raw, []any{ipv, v.Sg})
		case sgm.SgSgIcmpRuleID:
			ipv, e := ipFamilyFromModel(v.IPv)
			if e != nil {
				return e
			}
			raw = append(raw, []any{ipv, v.SgFrom, v.SgTo})
		case sgm.CidrSgRuleIdenity:
			var p Proto
			var t Traffic
			if err := p.FromModel(v.Transport); err != nil {
				return err
			}
			if err := t.FromModel(v.Traffic); err != nil {
				return err
			}
			raw = append(raw, []any{p, v.CIDR, v.SG, t})
		case sgm.SgSgRuleIdentity:
			var p Proto
			var t Traffic
			if err := p.FromModel(v.Transport); err != nil {
				return err
			}
			if err := t.FromModel(v.Traffic); err != nil {
				return err
			}
			raw = append(raw, []any{p, v.SgLocal, v.Sg, t})
		default:
			panic("UB")
		}
	}
	return o.flt.CopyFrom(ctx, raw, o.C)
}

// AddData -
func (o *syncObj[T, tFlt]) AddData(ctx context.Context, data ...T) error {
	o.ensureConstructed.Do(o.construct)
	if err := o.enureDataTable(ctx); err != nil {
		return err
	}
	var raw RawRowsData
	for _, d := range data {
		switch v := any(d).(type) {
		case sgm.Network:
			raw = append(raw, []any{v.Name, v.Net})
		case sgm.SecurityGroup:
			var sg SG
			sg.FromModel(v)
			raw = append(raw, []any{sg.Name, sg.Networks, sg.Logs, sg.Trace, sg.DefaultAction})
		case sgm.SGRule:
			var x SGRule
			if err := x.FromModel(v); err != nil {
				return err
			}
			raw = append(raw, []any{x.SgFrom, x.SgTo, x.Proto, x.Ports, x.Logs})
		case sgm.FQDNRule:
			var x SG2FQDNRule
			if err := x.FromModel(v); err != nil {
				return err
			}
			raw = append(raw, []any{x.SgFrom, x.FqndTo, x.Proto, x.Ports, x.Logs, x.NdpiProtocols})
		case sgm.SgIcmpRule:
			var x SgIcmpRule
			if err := x.FromModel(v); err != nil {
				return err
			}
			raw = append(raw, []any{x.IPv, x.Sg, x.Tytes, x.Logs, x.Trace})
		case sgm.SgSgIcmpRule:
			var x SgSgIcmpRule
			if err := x.FromModel(v); err != nil {
				return err
			}
			raw = append(raw, []any{x.IPv, x.SgFrom, x.SgTo, x.Tytes, x.Logs, x.Trace})
		case sgm.CidrSgRule:
			var x CidrSgRule
			if err := x.FromModel(v); err != nil {
				return err
			}
			raw = append(raw, []any{x.Proto, x.CIDR, x.SG, x.Traffic, x.Ports, x.Logs, x.Trace})
		case sgm.SgSgRule:
			var x SgSgRule
			if err := x.FromModel(v); err != nil {
				return err
			}
			raw = append(raw, []any{x.Proto, x.SgLocal, x.Sg, x.Traffic, x.Ports, x.Logs, x.Trace})
		default:
			panic("UB")
		}
	}
	return o.src.syncTable.CopyFrom(ctx, raw, o.C)
}

// Sync -
func (o *syncObj[T, tFlt]) Sync(ctx context.Context) (int64, error) {
	o.ensureConstructed.Do(o.construct)
	if err := o.enureDataTable(ctx); err != nil {
		return 0, err
	}
	actions := make([]func(io.Writer), 0, 3)
	if o.Upd && o.Ins {
		actions = append(actions, o.genUpsert)
	} else if o.Upd {
		actions = append(actions, o.genUpdate)
	} else if o.Ins {
		actions = append(actions, o.genInsert)
	}
	if o.Del {
		actions = append(actions, func(w io.Writer) {
			o.genDelete(w, o.flt.syncTable)
		})
	}
	var rowsAffected int64
	buf := bytes.NewBuffer(nil)
	for i := range actions {
		buf.Reset()
		actions[i](buf)
		sqlSmd := buf.String()
		row := o.C.QueryRow(ctx, sqlSmd)
		var n int
		if err := row.Scan(&n); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return rowsAffected, err
		}
		rowsAffected += int64(n)
	}
	return rowsAffected, nil
}
