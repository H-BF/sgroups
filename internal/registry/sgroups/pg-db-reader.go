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
	conn      func() (*pgx.Conn, error)
	close     func()
	getStatus func() *model.SyncStatus
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
	conn, err := rd.conn()
	if err != nil {
		return err
	}
	var rows pgx.Rows
	rows, err = conn.Query(ctx, fmt.Sprintf(`%s %s`, sel, from), args...)
	if err != nil {
		return err
	}
	scanner := pgx.RowToStructByName[pg.Network]
	err = pgxIterateRowsAndClose(rows, scanner, func(v pg.Network) error {
		return consume(model.Network{Name: v.Name, Net: v.Network})
	})
	return err
}

// ListSecurityGroups impl Reader interface
func (rd *pgDbReader) ListSecurityGroups(ctx context.Context, consume func(model.SecurityGroup) error, scope Scope) error {
	const (
		fnSgList = "sgroups.list_sg"
		fnSgFind = "sgroups.find_sg_by_network"
		sel      = `select "name", networks from`
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
	conn, err := rd.conn()
	if err != nil {
		return err
	}
	var rows pgx.Rows
	if rows, err = conn.Query(ctx, fmt.Sprintf(`%s %s`, sel, from), args...); err != nil {
		return err
	}
	scanner := pgx.RowToStructByName[model.SecurityGroup]
	err = pgxIterateRowsAndClose(rows, scanner, consume)
	return err
}

// ListSGRules impl Reader interface
func (rd *pgDbReader) ListSGRules(ctx context.Context, consume func(model.SGRule) error, scope Scope) error {
	const (
		fnRuleList = "sgroups.list_sg_rule"
		sel        = "select sg_from, sg_to, proto, ports from"
	)
	args := []any{pgx.QueryExecModeDescribeExec, nil, nil}
	var from string
	var fromSg []string
	var toSg []string
	var badScope bool
	switch sc := scope.(type) {
	case scopedAnd:
		from = fmt.Sprintf(`%s($1, $2)`, fnRuleList)
		for _, x := range []any{sc.L, sc.R} {
			switch a := x.(type) {
			case scopedSGFrom:
				for s := range a {
					if fromSg == nil {
						fromSg = make([]string, 0, len(a))
					}
					fromSg = append(fromSg, s)
				}
			case scopedSGTo:
				for s := range a {
					if toSg == nil {
						toSg = make([]string, 0, len(a))
					}
					toSg = append(toSg, s)
				}
			case noScope:
			default:
				badScope = true
			}
		}
		if fromSg != nil {
			args[1] = fromSg
		}
		if toSg != nil {
			args[2] = toSg
		}
	default:
		badScope = true
	}
	if badScope {
		return errors.WithMessagef(ErrUnexpectedScope, "%#v", scope)
	}
	conn, err := rd.conn()
	if err != nil {
		return err
	}
	var rows pgx.Rows
	if rows, err = conn.Query(ctx, fmt.Sprintf(`%s %s`, sel, from), args...); err != nil {
		return err
	}
	scanner := pgx.RowToStructByName[pg.SGRule]
	err = pgxIterateRowsAndClose(rows, scanner, func(rule pg.SGRule) error {
		m, e := rule.ToModel()
		if e == nil {
			e = consume(m)
		}
		return e
	})
	return err
}

// GetSyncStatus impl Reader interface
func (rd *pgDbReader) GetSyncStatus(_ context.Context) (*model.SyncStatus, error) {
	if rd.getStatus != nil {
		ret := rd.getStatus()
		return ret, nil
	}
	return nil, nil
}
