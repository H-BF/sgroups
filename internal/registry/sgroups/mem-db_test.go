package sgroups

import (
	"net"
	"testing"

	model "github.com/H-BF/sgroups/internal/models/sgroups"
	"github.com/hashicorp/go-memdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint
func Test_Db(t *testing.T) {
	db, err := NewMemDB(TblNetworks, TblSecGroups, TblSecRules)
	require.NoError(t, err)

	var n *net.IPNet
	_, n, err = net.ParseCIDR("10.0.0.0/24")
	require.NoError(t, err)

	nw := model.Network{
		Name: "net1",
		Net:  *n,
	}

	tx := db.Writer()

	err = tx.Upsert(TblNetworks, &nw)
	require.NoError(t, err)

	if false {
		nw2 := nw
		nw2.Name = "net2"
		err = tx.Upsert(TblNetworks, &nw2)
		require.NoError(t, err)
	}

	err = tx.Commit()
	if !assert.NoError(t, err) {
		i := 1
		i++
	}

	txr := db.Reader()
	var r interface{}
	r, err = txr.First(TblNetworks, indexID, "net1")
	require.NoError(t, err)
	r, err = txr.First(TblNetworks, indexID, "net2")
	require.NoError(t, err)

	_, err = txr.Get(TblNetworks, indexID, "net2")
	require.NoError(t, err)

	var it memdb.ResultIterator
	it, err = txr.Get(TblNetworks, indexIPNet, nw.Net)
	require.NoError(t, err)

	for r = it.Next(); r != nil; r = it.Next() {
		i := 1
		i++
	}

	it, err = txr.Get(TblNetworks, indexID)
	require.NoError(t, err)
	for r = it.Next(); r != nil; r = it.Next() {
		i := 1
		i++
	}

	it, err = txr.Get(TblNetworks, indexIPNet)
	require.NoError(t, err)
	for r = it.Next(); r != nil; r = it.Next() {
		i := 1
		i++
	}
}
