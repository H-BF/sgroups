package pg

import (
	"context"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pkg/errors"
)

type (
	// PortMumber -
	PortMumber = int32

	// PortRange -
	PortRange struct {
		pgtype.Range[PortMumber]
	}

	// PortMultirange -
	PortMultirange struct {
		pgtype.Multirange[PortRange]
	}

	// SgRulePorts -
	SgRulePorts struct {
		S PortMultirange
		D PortMultirange
	}

	// SgRulePortsArray -
	SgRulePortsArray []SgRulePorts

	// PortMultirangeArray -
	PortMultirangeArray []PortMultirange

	// Proto -
	Proto string

	// ChainDefaultAction -
	ChainDefaultAction string

	// Network -
	Network struct {
		Name    string    `db:"name"`
		Network net.IPNet `db:"network"`
	}

	// FQDN -
	FQDN string

	// SG -
	SG struct {
		Name          string             `db:"name"`
		Networks      []string           `db:"networks"`
		Logs          bool               `db:"logs"`
		Trace         bool               `db:"trace"`
		DefaultAction ChainDefaultAction `db:"default_action"`
	}

	// SGRule -
	SGRule struct {
		SgFrom string           `db:"sg_from"`
		SgTo   string           `db:"sg_to"`
		Proto  Proto            `db:"proto"`
		Ports  SgRulePortsArray `db:"ports"`
		Logs   bool             `db:"logs"`
	}

	// SG2FQDNRule -
	SG2FQDNRule struct {
		SgFrom string           `db:"sg_from"`
		FqndTo FQDN             `db:"fqdn_to"`
		Proto  Proto            `db:"proto"`
		Ports  SgRulePortsArray `db:"ports"`
		Logs   bool             `db:"logs"`
	}

	// SyncStatus -
	SyncStatus struct {
		Updtated          time.Time `db:"updated_at"`
		TotalAffectedRows int64     `db:"total_affected_rows"`
	}
)

// Load -
func (s *SyncStatus) Load(ctx context.Context, c *pgx.Conn) error {
	const qry = `select updated_at, total_affected_rows from sgroups.tbl_sync_status where id = (select max(id) from sgroups.tbl_sync_status)`
	r, e := c.Query(ctx, qry)
	if e != nil {
		return e
	}
	*s, e = pgx.CollectOneRow(r, pgx.RowToStructByName[SyncStatus])
	return e
}

// Store -
func (s SyncStatus) Store(ctx context.Context, c *pgx.Conn) error {
	_, e := c.Exec(
		ctx,
		"insert into sgroups.tbl_sync_status(total_affected_rows) values($1)",
		s.TotalAffectedRows)

	return e
}

// RegisterSGroupsTypesOntoPGX -
func RegisterSGroupsTypesOntoPGX(ctx context.Context, c *pgx.Conn) (err error) {
	defer func() {
		err = errors.WithMessage(err, "register 'sgroups' types onto PGX")
	}()
	var pgType *pgtype.Type
	pgTypeMap := c.TypeMap()
	if pgType, err = c.LoadType(ctx, "sgroups.port_ranges"); err != nil {
		return err
	}
	pgTypeMap.RegisterType(pgType)
	{
		var x PortMultirange
		pgTypeMap.RegisterDefaultPgType(x, pgType.Name)
		pgTypeMap.RegisterDefaultPgType(&x, pgType.Name)

		tn := pgType.Name + "_array"
		pgTypeMap.RegisterType(&pgtype.Type{
			Name:  tn,
			OID:   pgtype.Int4multirangeArrayOID,
			Codec: &pgtype.ArrayCodec{ElementType: pgType}},
		)
		var y PortMultirangeArray
		pgTypeMap.RegisterDefaultPgType(y, tn)
		pgTypeMap.RegisterDefaultPgType(&y, tn)
	}
	if pgType, err = c.LoadType(ctx, "sgroups.sg_rule_ports_prototype"); err != nil {
		return err
	}
	pgTypeMap.RegisterType(pgType)
	{
		oid := uint32(100001) //nolint:gomnd
		var x SgRulePorts
		pgTypeMap.RegisterDefaultPgType(x, pgType.Name)
		pgTypeMap.RegisterDefaultPgType(&x, pgType.Name)

		tn := pgType.Name + "_array"
		pgTypeMap.RegisterType(&pgtype.Type{
			Name:  tn,
			OID:   oid,
			Codec: &pgtype.ArrayCodec{ElementType: pgType},
		})
		var y SgRulePortsArray
		pgTypeMap.RegisterDefaultPgType(y, tn)
		pgTypeMap.RegisterDefaultPgType(&y, tn)
	}
	if pgType, err = c.LoadType(ctx, "sgroups.proto"); err != nil {
		return err
	}
	pgTypeMap.RegisterType(pgType)
	{
		var x Proto
		pgTypeMap.RegisterDefaultPgType(x, pgType.Name)
		pgTypeMap.RegisterDefaultPgType(&x, pgType.Name)
	}
	if pgType, err = c.LoadType(ctx, "sgroups.chain_default_action"); err != nil {
		return err
	}
	pgTypeMap.RegisterType(pgType)
	{
		var x ChainDefaultAction
		pgTypeMap.RegisterDefaultPgType(x, pgType.Name)
		pgTypeMap.RegisterDefaultPgType(&x, pgType.Name)
	}
	if _, err = c.Exec(ctx, "create extension if not exists citext"); err != nil {
		return err
	}
	//Register OID CITEXT extension
	citextExtType := pgtype.Type{Name: "citext", Codec: pgtype.TextCodec{}}
	err = c.QueryRow(ctx, "select $1::text::regtype::oid;", citextExtType.Name).
		Scan(&citextExtType.OID)
	if err != nil {
		return err
	}
	pgTypeMap.RegisterType(&citextExtType)
	if pgType, err = c.LoadType(ctx, "sgroups.fqdn"); err != nil {
		return err
	}
	pgTypeMap.RegisterType(pgType)
	{
		var x FQDN
		pgTypeMap.RegisterDefaultPgType(x, pgType.Name)
		pgTypeMap.RegisterDefaultPgType(&x, pgType.Name)
	}
	return nil
}
