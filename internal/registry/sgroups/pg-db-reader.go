package sgroups

import (
	"context"
	"fmt"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/internal/registry/sgroups/pg"

	"github.com/jackc/pgx/v5"
	"github.com/pkg/errors"
)

var _ Reader = (*pgDbReader)(nil)

type pgDbReader struct {
	doIt  func(context.Context, func(*pgx.Conn) error) error
	close func()
}

// Close impl Reader interface
func (rd *pgDbReader) Close() error {
	if rd.close != nil {
		rd.close()
	}
	return nil
}

func pgxIterateRowsAndClose[pgT any](rows pgx.Rows, scanner func(pgx.CollectableRow) (pgT, error), consumer func(pgT) error) error {
	defer rows.Close()
	for rows.Next() {
		v, err := scanner(rows)
		if err != nil {
			return err
		}
		if err = consumer(v); err != nil {
			return err
		}
	}
	return rows.Err()
}

// ListNetworks impl Reader interface
func (rd *pgDbReader) ListNetworks(ctx context.Context, consume func(model.Network) error, scope Scope) error {
	const (
		fnNetworkList = "sgroups.list_networks"
		fnNetworkFind = "sgroups.find_networks_from_ip"
		sel           = `select "name", network from`
	)
	var from string
	args := []any{pgx.QueryExecModeDescribeExec}
	switch sc := scope.(type) {
	case scopedIPs:
		//from = fmt.Sprintf(`%s($1)`, fnNetworkFind)
		//args = append(args, sc.IPs)// <-- TODO: Why it does not work
		from = fmt.Sprintf(`%s($1)`, fnNetworkFind)
		ips := make([]string, 0, len(sc.IPs))
		for _, ip := range sc.IPs {
			ips = append(ips, ip.String())
		}
		args = append(args, ips)
	case scopedNetworks:
		from = fmt.Sprintf(`%s($1)`, fnNetworkList)
		nwNames := make([]string, 0, len(sc.Names))
		for n := range sc.Names {
			nwNames = append(nwNames, n)
		}
		args = append(args, nwNames)
	case noScope:
		from = fmt.Sprintf(`%s()`, fnNetworkList)
	default:
		return errors.WithMessagef(ErrUnexpectedScope, "%#v", scope)
	}
	return rd.doIt(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, fmt.Sprintf(`%s %s`, sel, from), args...)
		if err != nil {
			return err
		}
		scanner := pgx.RowToStructByName[pg.Network]
		return pgxIterateRowsAndClose(rows, scanner, func(v pg.Network) error {
			return consume(model.Network{Name: v.Name, Net: v.Network})
		})
	})
}

// ListSecurityGroups impl Reader interface
func (rd *pgDbReader) ListSecurityGroups(ctx context.Context, consume func(model.SecurityGroup) error, scope Scope) error {
	const (
		fnSgList = "sgroups.list_sg"
		fnSgFind = "sgroups.find_sg_by_network"
		sel      = `select "name", networks, logs, trace, default_action from`
	)
	var from string
	args := []any{pgx.QueryExecModeDescribeExec}
	switch sc := scope.(type) {
	case scopedSG:
		from = fmt.Sprintf(`%s($1)`, fnSgList)
		sgNames := make([]string, 0, len(sc))
		for sgName := range sc {
			sgNames = append(sgNames, sgName)
		}
		args = append(args, sgNames)
	case scopedNetworks:
		nws := make([]string, 0, len(sc.Names))
		for n := range sc.Names {
			nws = append(nws, n)
		}
		from = fmt.Sprintf(`%s($1)`, fnSgFind)
		args = append(args, nws)
	case noScope:
		from = fmt.Sprintf(`%s()`, fnSgList)
	default:
		return errors.WithMessagef(ErrUnexpectedScope, "%#v", scope)
	}
	return rd.doIt(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, fmt.Sprintf(`%s %s`, sel, from), args...)
		if err != nil {
			return err
		}
		scanner := pgx.RowToStructByName[pg.SG]
		return pgxIterateRowsAndClose(rows, scanner, func(o pg.SG) error {
			m, e := o.ToModel()
			if e != nil {
				return e
			}
			return consume(m)
		})
	})
}

func (rd *pgDbReader) argsForListSGRules(scope Scope) ([]any, error) {
	var badScope bool
	var fromSg []string
	var toSg []string
	args := []any{pgx.QueryExecModeDescribeExec, nil, nil}
	switch sc := scope.(type) {
	case scopedAnd:
		for _, x := range []any{sc.L, sc.R} {
			switch a := x.(type) {
			case scopedSGFrom:
				for s := range a {
					fromSg = append(fromSg, s)
				}
			case scopedSGTo:
				for s := range a {
					toSg = append(toSg, s)
				}
			case noScope:
			default:
				badScope = true
			}
		}
	default:
		badScope = true
	}
	if badScope {
		return nil, errors.WithMessagef(ErrUnexpectedScope, "%#v", scope)
	}
	if fromSg != nil {
		args[1] = fromSg
	}
	if toSg != nil {
		args[2] = toSg
	}
	return args, nil
}

// ListSGRules impl Reader interface
func (rd *pgDbReader) ListSGRules(ctx context.Context, consume func(model.SGRule) error, scope Scope) error { //nolint:dupl
	const (
		qry = "select sg_from, sg_to, proto, ports, logs from sgroups.list_sg_rule($1, $2)"
	)
	args, err := rd.argsForListSGRules(scope)
	if err != nil {
		return err
	}
	return rd.doIt(ctx, func(c *pgx.Conn) error {
		rows, e := c.Query(ctx, qry, args...)
		if e != nil {
			return e
		}
		scanner := pgx.RowToStructByName[pg.SGRule]
		return pgxIterateRowsAndClose(rows, scanner, func(rule pg.SGRule) error {
			m, e1 := rule.ToModel()
			if e1 != nil {
				return e
			}
			return consume(m)
		})
	})
}

func (rd *pgDbReader) argsForListFQDNRules(scope Scope) ([]any, error) {
	var fromSg []string
	args := []any{pgx.QueryExecModeDescribeExec, nil}
	switch sc := scope.(type) {
	case scopedSGFrom:
		fromSg = make([]string, 0, len(sc))
		for s := range sc {
			fromSg = append(fromSg, s)
		}
	case noScope:
	default:
		return nil, errors.WithMessagef(ErrUnexpectedScope, "%#v", scope)
	}
	if fromSg != nil {
		args[1] = fromSg
	}
	return args, nil
}

// ListFqdnRules impl Reader interface
func (rd *pgDbReader) ListFqdnRules(ctx context.Context, consume func(model.FQDNRule) error, scope Scope) error { //nolint:dupl
	const (
		qry = "select sg_from, fqdn_to, proto, ports, logs from sgroups.list_fqdn_rule($1)"
	)
	args, err := rd.argsForListFQDNRules(scope)
	if err != nil {
		return err
	}
	return rd.doIt(ctx, func(c *pgx.Conn) error {
		rows, e := c.Query(ctx, qry, args...)
		if e != nil {
			return e
		}
		scanner := pgx.RowToStructByName[pg.SG2FQDNRule]
		return pgxIterateRowsAndClose(rows, scanner, func(rule pg.SG2FQDNRule) error {
			m, e1 := rule.ToModel()
			if e1 != nil {
				return e
			}
			return consume(m)
		})
	})
}

func (rd *pgDbReader) argsForListSgIcmpRules(scope Scope) ([]any, error) {
	var sgs []string
	switch sc := scope.(type) {
	case scopedSG:
		for s := range sc {
			sgs = append(sgs, s)
		}
	case noScope:
	default:
		return nil, errors.WithMessagef(ErrUnexpectedScope, "%#v", scope)
	}
	args := []any{pgx.QueryExecModeDescribeExec, nil}
	if sgs != nil {
		args[1] = sgs
	}
	return args, nil
}

// ListSgIcmpRule impl Reader
func (rd *pgDbReader) ListSgIcmpRules(ctx context.Context, consume func(model.SgIcmpRule) error, scope Scope) error { //nolint:dupl
	const (
		qry = "select ip_v, types, sg, logs, trace from sgroups.list_sg_icmp_rule($1)"
	)
	args, err := rd.argsForListSgIcmpRules(scope)
	if err != nil {
		return err
	}
	return rd.doIt(ctx, func(c *pgx.Conn) error {
		rows, e := c.Query(ctx, qry, args...)
		if e != nil {
			return e
		}
		scanner := pgx.RowToStructByName[pg.SgIcmpRule]
		return pgxIterateRowsAndClose(rows, scanner, func(rule pg.SgIcmpRule) error {
			m, e1 := rule.ToModel()
			if e1 != nil {
				return e
			}
			return consume(m)
		})
	})
}

func (rd *pgDbReader) argsForListSgSgIcmpRules(scope Scope) ([]any, error) {
	var sgFrom []string
	var sgTo []string
	var badScope bool
	switch sc := scope.(type) {
	case scopedAnd:
		for _, x := range []any{sc.L, sc.R} {
			switch a := x.(type) {
			case scopedSGFrom:
				for s := range a {
					sgFrom = append(sgFrom, s)
				}
			case scopedSGTo:
				for s := range a {
					sgTo = append(sgTo, s)
				}
			case noScope:
			default:
				badScope = true
			}
		}
	default:
		badScope = true
	}
	if badScope {
		return nil, errors.WithMessagef(ErrUnexpectedScope, "%#v", scope)
	}
	args := []any{pgx.QueryExecModeDescribeExec, nil, nil}
	if sgFrom != nil {
		args[1] = sgFrom
	}
	if sgTo != nil {
		args[2] = sgTo
	}
	return args, nil
}

// ListSgSgIcmpRules impl Reader
func (rd *pgDbReader) ListSgSgIcmpRules(ctx context.Context, consume func(model.SgSgIcmpRule) error, scope Scope) error { //nolint:dupl
	const (
		qry = "select ip_v, types, sg_from, sg_to, logs, trace from sgroups.list_sg_sg_icmp_rule($1, $2)"
	)
	args, err := rd.argsForListSgSgIcmpRules(scope)
	if err != nil {
		return err
	}
	return rd.doIt(ctx, func(c *pgx.Conn) error {
		rows, e := c.Query(ctx, qry, args...)
		if e != nil {
			return e
		}
		scanner := pgx.RowToStructByName[pg.SgSgIcmpRule]
		return pgxIterateRowsAndClose(rows, scanner, func(rule pg.SgSgIcmpRule) error {
			m, e1 := rule.ToModel()
			if e1 != nil {
				return e
			}
			return consume(m)
		})
	})
}

// GetSyncStatus impl Reader interface
func (rd *pgDbReader) GetSyncStatus(ctx context.Context) (*model.SyncStatus, error) {
	const api = "PG/GetSyncStatus"
	var ret *model.SyncStatus
	err := rd.doIt(ctx, func(c *pgx.Conn) error {
		var s pg.SyncStatus
		e := s.Load(ctx, c)
		if e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return nil
			}
			return e
		}
		ret = &model.SyncStatus{
			UpdatedAt: s.Updtated,
		}
		return nil
	})
	return ret, errors.WithMessage(err, api)
}
