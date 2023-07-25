package pg

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"time"
	"unsafe"

	"github.com/jackc/pgx/v5"
	"github.com/pkg/errors"
)

type (
	syncField struct {
		Name    string
		PgTy    string
		Notnull bool
		Pk      bool
	}

	syncTable struct {
		Name     string
		Temporay bool
		OnCommit string

		fields []syncField
	}

	syncGenSQL struct {
		tableDst  syncTable
		dataTable string
		mutatorFn string
	}
)

//=========================================== syncTable ========================================*

// WithFields --
func (t syncTable) WithFields(fds ...syncField) syncTable {
	t.fields = append([]syncField(nil), fds...)
	return t
}

// WithRandomName -
func (t syncTable) WithRandomName(prefix, suffix string) syncTable {
	n := time.Now().UnixNano()
	dat := struct {
		n1 int64
		n2 int64
	}{n, rand.NewSource(n).Int63()}
	type bb = [unsafe.Sizeof(dat)]byte
	h := md5.Sum((*bb)(unsafe.Pointer(&dat))[:])
	alnum := []byte("abcdefghijklmmopqrstuvwxyz1234567890")
	al := []byte("abcdefghijklmmopqrstuvwxyz")
	rand.Shuffle(len(alnum), func(i, j int) {
		alnum[i], alnum[j] = alnum[j], alnum[i]
	})
	rand.Shuffle(len(al), func(i, j int) {
		al[i], al[j] = al[j], al[i]
	})
	buf := bytes.NewBuffer(nil)
	buf.WriteString(prefix)
	for i := 0; i < len(h); i += 2 {
		if i == 0 {
			nn := *(*uint16)(unsafe.Pointer(&h[i])) % uint16(len(al))
			buf.WriteByte(al[nn])
		} else {
			nn := *(*uint16)(unsafe.Pointer(&h[i])) % uint16(len(alnum))
			buf.WriteByte(alnum[nn])
		}
	}
	buf.WriteString(suffix)
	t.Name = buf.String()
	return t
}

// PkFieldNames -
func (t syncTable) PkFieldNames() []string {
	ret := make([]string, 0, len(t.fields))
	for _, f := range t.fields {
		if f.Pk {
			ret = append(ret, f.Name)
		}
	}
	return ret
}

// FieldNames -
func (t syncTable) FieldNames() []string {
	ret := make([]string, 0, len(t.fields))
	for _, f := range t.fields {
		ret = append(ret, f.Name)
	}
	return ret
}

// Create -
func (t syncTable) Create(ctx context.Context, c *pgx.Conn) error {
	s := t.createScript()
	_, err := c.Exec(ctx, s)
	if t.Temporay {
		errors.WithMessagef(err, "on create temp table '%s'", t.Name)
	}
	return errors.WithMessagef(err, "on create table '%s'", t.Name)
}

// CopyFrom -
func (t syncTable) CopyFrom(ctx context.Context, raw RawRowsData, c *pgx.Conn) error {
	var copied int64
	for raw.Len() > copied {
		d := raw.ToPgxCopySource(copied)
		n, e := c.CopyFrom(ctx, pgx.Identifier{t.Name}, t.FieldNames(), d)
		if e != nil {
			return e
		}
		if n == 0 {
			return errors.New("copy-from has stuck")
		}
		copied += n
	}
	return nil
}

func (t syncTable) createScript() string {
	b := bytes.NewBuffer(nil)
	b.WriteString("create ")
	if t.Temporay {
		b.WriteString("temp ")
	}
	fmt.Fprintf(b, "table %s (\n", t.Name)
	var pk []string
	for i := range t.fields {
		b.WriteByte('\t')
		if i > 0 {
			b.WriteString(", ")
		}
		f := t.fields[i]
		fmt.Fprintf(b, "%s %s", f.Name, f.PgTy)
		if f.Notnull || f.Pk {
			b.WriteString(" not null")
		}
		b.WriteString("\n")
		if f.Pk {
			pk = append(pk, f.Name)
		}
	}
	if len(pk) > 0 {
		fmt.Fprintf(b, "\n\t, primary key(%s)", strings.Join(pk, ","))
	}
	b.WriteString("\n)")
	if len(t.OnCommit) > 0 {
		fmt.Fprintf(b, " on commit %s", t.OnCommit)
	}
	return b.String()
}

//=========================================== syncGenSQL ========================================*

func (hlp *syncGenSQL) genSemanticUdpate(w io.Writer, op string) {
	wr := writer{w}
	fds := hlp.tableDst.FieldNames()
	wr.WriteString("with ")
	hlp.cte(w, "data", false, func(w1 io.Writer) {
		wr1 := writer{w1}
		fmt.Fprintf(wr1, "select %s from %s",
			strings.Join(fds, ", "),
			hlp.dataTable)
	}, fds...)
	wr.WriteString(" select count(")
	hlp.callMutator(wr, op, "data", hlp.tableDst.fields)
	wr.WriteString(") as c from data")
}

func (hlp *syncGenSQL) genUpsert(w io.Writer) {
	hlp.genSemanticUdpate(w, "ups")
}

func (hlp *syncGenSQL) genInsert(w io.Writer) {
	hlp.genSemanticUdpate(w, "ins")
}

func (hlp *syncGenSQL) genUpdate(w io.Writer) {
	hlp.genSemanticUdpate(w, "upd")
}

func (hlp *syncGenSQL) genDelete(w io.Writer, flt *syncTable) {
	wr := writer{w}
	wr.WriteString("with ")
	hlp.old(w, "old", flt)
	wr.WriteString(", ")
	hlp.cteDel(w, "old", "del")
	wr.WriteString(" select count(")
	hlp.callMutator(w, "del", "del", hlp.tableDst.fields)
	wr.WriteString(") as c from del")
}

func (hlp *syncGenSQL) old(w io.Writer, alias string, tableFlt *syncTable) {
	hlp.cte(w, alias, false, func(w io.Writer) {
		if tableFlt != nil {
			fds := tableFlt.FieldNames()
			hlp.join(w,
				hlp.tableDst.Name,
				false,
				tableFlt.Name,
				hlp.tableDst.FieldNames(),
				fds...)
		} else {
			fmt.Fprintf(w, "select %s from %s",
				strings.Join(hlp.tableDst.FieldNames(), ", "),
				hlp.tableDst.Name)
		}
	}, hlp.tableDst.FieldNames()...)
}

/*// TODO: Remove this
func (hlp *syncGenSQL) cteInsOrUpd(w io.Writer, aliasOld, aliasInsOrUpd string, isForInsert bool) {
	outFields := hlp.tableDst.FieldNames()
	pkFields := hlp.tableDst.PkFieldNames()
	if len(pkFields) == 0 {
		panic("no any pk field")
	}
	hlp.cte(w, aliasInsOrUpd, false, func(w io.Writer) {
		hlp.join(w,
			hlp.dataTable,
			isForInsert,
			aliasOld,
			outFields,
			pkFields...,
		)
		if isForInsert {
			fmt.Fprintf(w, " where %s.%s is null", aliasOld, pkFields[0])
		}
	}, outFields...)
}
*/

func (hlp *syncGenSQL) cteDel(w io.Writer, aliasOld, aliasDelete string) {
	outFields := hlp.tableDst.FieldNames()
	pkFields := hlp.tableDst.PkFieldNames()
	if len(pkFields) == 0 {
		panic("no any pk field")
	}
	hlp.cte(w, aliasDelete, false, func(w io.Writer) {
		if hlp.dataTable != "" {
			hlp.join(w,
				aliasOld,
				true,
				hlp.dataTable,
				outFields,
				pkFields...,
			)
			fmt.Fprintf(w, " where %s.%s is null", hlp.dataTable, pkFields[0])
		} else {
			fmt.Fprintf(w, "select %s from %s", strings.Join(outFields, ", "), aliasOld)
		}
	}, outFields...)
}

func (*syncGenSQL) cte(w io.Writer, alias string, recursive bool, body func(io.Writer), fds ...string) {
	wr := writer{w}
	if recursive {
		wr.WriteString("recursive ")
	}
	fmt.Fprintf(wr, "%s", alias)
	if len(fds) > 0 {
		fmt.Fprintf(wr, "(%s)", strings.Join(fds, ", "))
	}
	wr.WriteString(" as (")
	body(w)
	wr.WriteByte(')')
}

func (hlp *syncGenSQL) join(w io.Writer, aliasL string, outer bool, aliasR string, fdsOut []string, joinFds ...string) {
	b := writer{w}
	b.WriteString("select ")
	for i, f := range fdsOut {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%s.%s", aliasL, f)
	}
	fmt.Fprintf(b, " from %s", aliasL)
	if outer {
		b.WriteString(" left outer")
	}
	fmt.Fprintf(b, " join %s on ", aliasR)
	if len(joinFds) == 0 {
		b.WriteString("true")
	} else {
		hlp.fieldsEq(b, aliasL, aliasR, joinFds...)
	}
}

func (hlp *syncGenSQL) callMutator(w io.Writer, typeOfMutate, alias string, fds []syncField) {
	b := writer{w}
	fmt.Fprintf(b, "%s('%s', row(", hlp.mutatorFn, typeOfMutate)
	for i, f := range fds {
		if i > 0 {
			b.WriteString(", ")
		}
		if len(alias) > 0 {
			fmt.Fprintf(b, "%s.", alias)
		}
		b.WriteString(f.Name)
	}
	b.WriteString("))")
}

func (*syncGenSQL) fieldsEq(w io.Writer, aliasL, aliasR string, fds ...string) {
	b := writer{w}
	for i, f := range fds {
		if i > 0 {
			b.WriteString(" and ")
		}
		if len(aliasL) > 0 {
			fmt.Fprintf(b, "%s.", aliasL)
		}
		fmt.Fprintf(b, "%s = ", f)
		if len(aliasR) > 0 {
			fmt.Fprintf(b, "%s.", aliasR)
		}
		b.WriteString(f)
	}
}
