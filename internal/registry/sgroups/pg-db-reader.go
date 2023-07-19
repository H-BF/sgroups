package sgroups

import (
	"context"
	"fmt"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/H-BF/sgroups/internal/registry/sgroups/pg"
	"github.com/pkg/errors"

	"github.com/jackc/pgx/v5"
)

var _ Reader = (*pgDbReader)(nil)

type pgDbReader struct {
	conn  func() (*pgx.Conn, error)
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
	var args pgx.NamedArgs
	switch sc := scope.(type) {
	case scopedIPs:
		from = fmt.Sprintf(`%s(@ips)`, fnNetworkFind)
		args = pgx.NamedArgs{
			"ips": sc.IPs,
		}
	case scopedNetworks:
		from = fmt.Sprintf(`%s(@names)`, fnNetworkList)
		if n := len(sc.Names); n > 0 {
			nwNames := make([]string, 0, n)
			for n := range sc.Names {
				nwNames = append(nwNames, n)
			}
			args = pgx.NamedArgs{"names": nwNames}
		}
	case noScope:
		from = fmt.Sprintf(`%s()`, fnNetworkList)
	default:
		return errors.WithMessagef(ErrUnexpectedScope, "%Т", scope)
	}
	conn, err := rd.conn()
	if err != nil {
		return err
	}
	var rows pgx.Rows
	if rows, err = conn.Query(ctx, fmt.Sprintf(`%s %s`, sel, from), args); err != nil {
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
	var args pgx.NamedArgs
	switch sc := scope.(type) {
	case scopedSG:
		from = fmt.Sprintf(`%s(@names)`, fnSgList)
		if n := len(sc); n > 0 {
			sgNames := make([]string, 0, n)
			for sgName := range sc {
				sgNames = append(sgNames, sgName)
			}
			args = pgx.NamedArgs{"names": sgNames}
		}
	case scopedNetworks:
		nws := make([]string, 0, len(sc.Names))
		for n := range sc.Names {
			nws = append(nws, n)
		}
		from = fmt.Sprintf(`%s(@networks)`, fnSgFind)
		args = pgx.NamedArgs{"networks": nws}
	case noScope:
		from = fmt.Sprintf(`%s()`, fnSgList)
	default:
		return errors.WithMessagef(ErrUnexpectedScope, "%Т", scope)
	}
	conn, err := rd.conn()
	if err != nil {
		return err
	}
	var rows pgx.Rows
	if rows, err = conn.Query(ctx, fmt.Sprintf(`%s %s`, sel, from), args); err != nil {
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

		argSgFrom = "sgfrom"
		argSgTo   = "sgto"
	)
	var from string
	args := pgx.NamedArgs{
		argSgFrom: nil,
		argSgTo:   nil,
	}
	switch sc := scope.(type) {
	case scopedAnd:
		from = fmt.Sprintf(`%s(@%s, @%s)`, fnRuleList, argSgFrom, argSgTo)
		if scSgFrom, ok := sc.L.(scopedSGFrom); !ok {
			return errors.WithMessagef(ErrUnexpectedScope, "%Т", sc.L)
		} else if n := len(scSgFrom); n > 0 {
			names := make([]string, 0, n)
			for s := range scSgFrom {
				names = append(names, s)
			}
			args[argSgFrom] = names
		}
		if scSgTo, ok := sc.R.(scopedSGTo); !ok {
			return errors.WithMessagef(ErrUnexpectedScope, "%Т", sc.R)
		} else if n := len(scSgTo); n > 0 {
			names := make([]string, 0, n)
			for s := range scSgTo {
				names = append(names, s)
			}
			args[argSgTo] = names
		}
	default:
		return errors.WithMessagef(ErrUnexpectedScope, "%Т", scope)
	}
	conn, err := rd.conn()
	if err != nil {
		return err
	}
	var rows pgx.Rows
	if rows, err = conn.Query(ctx, fmt.Sprintf(`%s %s`, sel, from), args); err != nil {
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
func (rd *pgDbReader) GetSyncStatus(ctx context.Context) (*model.SyncStatus, error) {
	return nil, nil
}
