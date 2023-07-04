package db

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"
)

type (
	// SqlxRow just alias
	SqlxRow = sqlx.Row
	// SqlxRows just alias
	SqlxRows = sqlx.Rows

	// SqlxPrepare preparer interface
	SqlxPrepare interface {
		Prepare(query string) (SqlxStatement, error)
		PrepareContext(ctx context.Context, query string) (SqlxStatement, error)
		PrepareNamed(query string) (SqlxNamedStatement, error)
		PrepareNamedContext(ctx context.Context, query string) (SqlxNamedStatement, error)
	}

	// SqlxExec exec interface
	SqlxExec interface {
		Exec(query string, args ...interface{}) (sql.Result, error)
		ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
		NamedExec(query string, arg interface{}) (sql.Result, error)
		NamedExecContext(ctx context.Context, query string, arg interface{}) (sql.Result, error)
	}

	// SqlxQuery query Rows interface
	SqlxQuery interface {
		Query(query string, args ...interface{}) (*sql.Rows, error)
		QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
		Queryx(query string, args ...interface{}) (*SqlxRows, error)
		QueryxContext(ctx context.Context, query string, args ...interface{}) (*SqlxRows, error)
		NamedQuery(query string, arg interface{}) (*SqlxRows, error)
		NamedQueryContext(ctx context.Context, query string, arg interface{}) (*SqlxRows, error)
	}

	// SqlxQueryRow query row interface
	SqlxQueryRow interface {
		QueryRow(query string, args ...interface{}) *sql.Row
		QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
		QueryRowx(query string, args ...interface{}) *SqlxRow
		QueryRowxContext(ctx context.Context, query string, args ...interface{}) *SqlxRow
	}

	// SqlxSelect select interface
	SqlxSelect interface {
		Select(dest interface{}, query string, args ...interface{}) error
		SelectContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	}

	// SqlxGet Get interface
	SqlxGet interface {
		Get(dest interface{}, query string, args ...interface{}) error
		GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error
	}

	// SqlxStatement prepared statement interface
	SqlxStatement interface {
		Unsafe() SqlxStatement
		Close() error

		QueryRow(args ...interface{}) *sql.Row
		QueryRowContext(ctx context.Context, args ...interface{}) *sql.Row
		QueryRowx(args ...interface{}) *SqlxRow
		QueryRowxContext(ctx context.Context, args ...interface{}) *SqlxRow

		Queryx(args ...interface{}) (*SqlxRows, error)
		QueryxContext(ctx context.Context, args ...interface{}) (*SqlxRows, error)

		Exec(args ...interface{}) (sql.Result, error)
		ExecContext(ctx context.Context, args ...interface{}) (sql.Result, error)
		Query(args ...interface{}) (*sql.Rows, error)
		QueryContext(ctx context.Context, args ...interface{}) (*sql.Rows, error)
		Select(dest interface{}, args ...interface{}) error
		SelectContext(ctx context.Context, dest interface{}, args ...interface{}) error
		Get(dest interface{}, args ...interface{}) error
		GetContext(ctx context.Context, dest interface{}, args ...interface{}) error
	}

	// SqlxNamedStatement prepared named statement interface
	SqlxNamedStatement interface {
		Unsafe() SqlxNamedStatement
		Close() error

		/*//
		Rebind(string) string
		BindNamed(string, interface{}) (string, []interface{}, error)
		*/

		QueryRow(arg interface{}) *SqlxRow
		QueryRowContext(ctx context.Context, arg interface{}) *SqlxRow
		QueryRowx(arg interface{}) *SqlxRow
		QueryRowxContext(ctx context.Context, arg interface{}) *SqlxRow

		Queryx(arg interface{}) (*SqlxRows, error)
		QueryxContext(ctx context.Context, arg interface{}) (*SqlxRows, error)

		Exec(arg interface{}) (sql.Result, error)
		ExecContext(ctx context.Context, arg interface{}) (sql.Result, error)
		Query(arg interface{}) (*sql.Rows, error)
		QueryContext(ctx context.Context, arg interface{}) (*sql.Rows, error)
		Select(dest interface{}, arg interface{}) error
		SelectContext(ctx context.Context, dest interface{}, arg interface{}) error
		Get(dest interface{}, arg interface{}) error
		GetContext(ctx context.Context, dest interface{}, arg interface{}) error
	}

	// SqlxQueryEngine essential sql-x query engine
	SqlxQueryEngine interface {
		SqlxPrepare
		SqlxExec
		SqlxQuery
		SqlxQueryRow
		SqlxSelect
		SqlxGet
	}

	// SqlxEngine ...
	SqlxEngine interface {
		SqlxQueryEngine
		Close() error
		Rebind(query string) string
		BindNamed(query string, arg interface{}) (string, []interface{}, error)
		Unsafe() SqlxEngine
	}

	// SqlxDatabase database interface
	SqlxDatabase interface {
		SqlxEngine
		Begin(opts *sql.TxOptions) (SqlxTransaction, error)
		BeginContext(ctx context.Context, opts *sql.TxOptions) (SqlxTransaction, error)
	}

	// SqlxTransaction transaction interface
	SqlxTransaction interface {
		SqlxEngine
		Stmtx(stmt interface{}) SqlxStatement
		StmtxContext(ctx context.Context, stmt interface{}) SqlxStatement
		End(doCommit bool) error
	}
)
