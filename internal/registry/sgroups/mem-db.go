package sgroups

import (
	"sync"

	"github.com/H-BF/corlib/pkg/dict"
	"github.com/hashicorp/go-memdb"
	"github.com/pkg/errors"
)

// IndexID alias to string
type IndexID = string

const ( //indexes
	indexID             IndexID = "id"
	indexIPNet          IndexID = "ip-net"
	indexSG             IndexID = "sg"
	indexProtoSgTraffic IndexID = "proto-sg-traffic"
	indexIPvSgTraffic   IndexID = "IPv-sg-traffic"
)

type (
	// MemDbIterator alias to memdb.ResultIterator
	MemDbIterator = memdb.ResultIterator

	// MemDbSchema alias to memdb.DBSchema
	MemDbSchema = memdb.DBSchema

	// MemDbTableSchema alias to memdb.TableSchema
	MemDbTableSchema = memdb.TableSchema

	// MemDbIndexSchema alias to memdb.IndexSchema
	MemDbIndexSchema = memdb.IndexSchema

	// MemDbStringFieldIndex alias to MemDbStringFieldIndex
	MemDbStringFieldIndex = memdb.StringFieldIndex

	// MemDB memory db impl
	MemDB interface {
		Reader() MemDbReader
		Writer() MemDbWriter
		Schema() *MemDbSchema
	}

	// MemDbOption update option
	MemDbOption interface {
		privateMemDbOption()
	}

	// MemDbSchemaInit init mem db schema Option
	MemDbSchemaInit func(*MemDbSchema)

	// IntegrityChecker mem db data integrity checker
	IntegrityChecker func(MemDbReader) error

	// MemDBTables is a MemDbOption
	MemDBTables []TableID

	// MemDbReader reader interface
	MemDbReader interface {
		First(tabName TableID, index IndexID, args ...interface{}) (interface{}, error)
		Get(tabName TableID, index IndexID, args ...interface{}) (MemDbIterator, error)
	}

	// MemDbWriter writer interface
	MemDbWriter interface {
		MemDbReader
		Commit() error
		Abort()
		Upsert(tabName TableID, obj interface{}) error
		Delete(tabName TableID, obj interface{}) error
		DeleteAll(tabName TableID, index IndexID, args ...interface{}) (int, error)
	}
)

// AllTables -
func AllTables() MemDbOption {
	return MemDBTables([]TableID{
		TblNetworks, TblSecGroups, TblSecRules,
		TblSyncStatus, TblFqdnRules, TblSgIcmpRules,
		TblSgSgIcmpRules, TblIECidrSgIcmpRules, TblCidrSgRules,
		TblSgSgRules, TblIESgSgIcmpRules,
	})
}

// NewMemDB creates memory db instance
func NewMemDB(opts ...MemDbOption) (MemDB, error) {
	var seenTables dict.HSet[TableID]
	sch := &memdb.DBSchema{Tables: make(map[string]*memdb.TableSchema)}
	var checks []IntegrityChecker
	for i := range opts {
		switch o := opts[i].(type) {
		case MemDBTables:
			for _, t := range o {
				if seenTables.Insert(t) {
					t.memDbSchema()(sch)
					checks = append(checks, t.IntegrityChecks()...)
				}
			}
		case MemDbSchemaInit:
			o(sch)
		case IntegrityChecker:
			checks = append(checks, o)
		}
	}
	var err error
	var ret memDb
	if ret.db, err = memdb.NewMemDB(sch); err == nil {
		ret.integrityChecker = checks
	}
	return ret, err
}

var _ MemDB = (*memDb)(nil)

type memDb struct {
	db               *memdb.MemDB
	integrityChecker []IntegrityChecker
}

type memDbReader struct {
	tx *memdb.Txn
}

type memDbWriter struct {
	*memDbReader
	memDb
	commitOnce sync.Once
}

func (db memDb) Writer() MemDbWriter {
	return &memDbWriter{
		memDb:       db,
		memDbReader: &memDbReader{tx: db.db.Txn(true)},
	}
}

func (db memDb) Reader() MemDbReader {
	return &memDbReader{
		tx: db.db.Txn(false),
	}
}

func (db memDb) Schema() *MemDbSchema {
	return db.db.DBSchema()
}

func (tx *memDbReader) First(tabName TableID, index IndexID, args ...interface{}) (interface{}, error) {
	return tx.tx.First(tabName.String(), index, args...)
}

func (tx *memDbReader) Get(tabName TableID, index IndexID, args ...interface{}) (MemDbIterator, error) {
	return tx.tx.Get(tabName.String(), index, args...)
}

func (tx *memDbWriter) Commit() error {
	err := ErrWriterClosed
	tx.commitOnce.Do(func() {
		if err = tx.checkIndexesViolation(); err == nil {
			err = tx.checkIntegrity()
		}
		if err == nil {
			tx.tx.Commit()
		} else {
			tx.tx.Abort()
		}
	})
	return err
}

func (tx *memDbWriter) Abort() {
	tx.commitOnce.Do(func() {
		tx.tx.Abort()
	})
}

func (tx *memDbWriter) Upsert(tabName TableID, obj interface{}) error {
	return tx.tx.Insert(tabName.String(), obj)
}

func (tx *memDbWriter) Delete(tabName TableID, obj interface{}) error {
	return tx.tx.Delete(tabName.String(), obj)
}

func (tx *memDbWriter) DeleteAll(tabName TableID, index IndexID, args ...interface{}) (int, error) {
	return tx.tx.DeleteAll(tabName.String(), index, args...)
}

func (tx *memDbWriter) checkIntegrity() error {
	for _, c := range tx.integrityChecker {
		if e := c(tx); e != nil {
			return e
		}
	}
	return nil
}

func (tx *memDbWriter) checkIndexesViolation() error {
	schema := tx.memDb.Schema()
	for _, t := range schema.Tables {
		r, e := tx.tx.Get(t.Name, t.Indexes[indexID].Name)
		if e != nil {
			return e
		}
		cnt := 0
		for x := r.Next(); x != nil; x = r.Next() {
			cnt++
		}
		for _, i := range t.Indexes {
			if i.Name != indexID && i.Unique && !i.AllowMissing {
				if r, e = tx.tx.Get(t.Name, i.Name); e != nil {
					return e
				}
				cnt2 := 0
				for x := r.Next(); x != nil; x = r.Next() {
					cnt2++
				}
				if cnt2 != cnt {
					return errors.Errorf("unique index [%s].[%s] is violated",
						t.Name, i.Name)
				}
			}
		}
	}
	return nil
}

func (MemDbSchemaInit) privateMemDbOption()  {}
func (IntegrityChecker) privateMemDbOption() {}
func (MemDBTables) privateMemDbOption()      {}
