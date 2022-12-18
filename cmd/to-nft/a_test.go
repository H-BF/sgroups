package main

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"

	nft "github.com/google/nftables"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestA(t *testing.T) {
	nl, err := netlink.NewHandle()
	require.NoError(t, err)
	links, err := nl.LinkList()
	require.NoError(t, err)
	for i := range links {
		d := links[i]
		if fl := d.Attrs().Flags; fl&net.FlagUp == 0 || fl&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := nl.AddrList(d, netlink.FAMILY_ALL)
		require.NoError(t, err)

		_ = addrs

	}
}

func TestB(t *testing.T) {
	//ctx, can := context.WithTimeout(context.Background(), 5*time.Second)
	ctx, can := context.WithCancel(context.Background())
	defer can()
	ch := make(chan netlink.LinkUpdate)
	err := netlink.LinkSubscribe(ch, ctx.Done())
	require.NoError(t, err)
	for c := range ch {
		s := c.Type()
		switch c.Header.Type {
		case unix.RTM_NEWLINK:
			s += "/created"
		case unix.RTM_DELLINK:
			s += "/deleted"
		default:
			s += "/updated"
		}
		fmt.Println(s)
	}
	//netlink.AddrUpdate
	//netlink.AddrSubscribe()
}

func TestC(t *testing.T) {
	ctx, can := context.WithCancel(context.Background())
	defer can()
	ch := make(chan netlink.AddrUpdate)
	err := netlink.AddrSubscribe(ch, ctx.Done())
	require.NoError(t, err)
	for c := range ch {
		var s string
		if c.NewAddr {
			s = "+"
		} else {
			s = "-"
		}
		fmt.Printf("link #%v ADDR %s (%s)\n", c.LinkIndex, s, &c.LinkAddress)
	}
}

func TestD(t *testing.T) {
	ctx, can := context.WithCancel(context.Background())
	defer can()

	chLinks := make(chan netlink.LinkUpdate)
	err := netlink.LinkSubscribe(chLinks, ctx.Done())
	require.NoError(t, err)
	chAddr := make(chan netlink.AddrUpdate)
	err = netlink.AddrSubscribe(chAddr, ctx.Done())
	require.NoError(t, err)
	cases := []reflect.SelectCase{
		{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(chLinks),
		},
		{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(chAddr),
		},
		{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ctx.Done()),
		},
	}

	for {
		_, recv, recvOK := reflect.Select(cases)
		if !recvOK {
			break
		}
		switch v := recv.Interface().(type) {
		case netlink.AddrUpdate:
			var s string
			if v.NewAddr {
				s = "+"
			} else {
				s = "-"
			}
			fmt.Printf("link #%v ADDR %s (%s)\n", v.LinkIndex, s, &v.LinkAddress)
		case netlink.LinkUpdate:
			s := v.Type()
			switch v.Header.Type {
			case unix.RTM_NEWLINK:
				s += "/upsert"
			case unix.RTM_DELLINK:
				s += "/delete"
			}
			fmt.Println(s)
		case struct{}:
			return
		}
	}
}

func Test_1_Nft(t *testing.T) {

	c, e := nft.New(nft.AsLasting())

	require.NoError(t, e)
	defer c.CloseLasting()

	tbl := nft.Table{
		Name:   "tbl1",
		Family: nft.TableFamilyINet,
	}
	tt := c.AddTable(&tbl)
	require.NotNil(t, tt)
	tabs, e := c.ListTables()
	_ = e
	_ = tabs
	//require.NoError(t, e)

	//e = c.Flush()
	//require.Not(t, e)

	//i := 1
	//i++
	//_ = tabs

	//nft.Table

	//tbs, e := c.ListTables()

}
