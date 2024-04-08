package main

import (
	"context"
	"fmt"
	"github.com/google/nftables"
)

func trace() {
	conn, err := nftables.New()
	if err != nil {
		panic("conn err: " + err.Error())
	}
	tables, err := conn.ListTables()
	if err != nil {
		panic("list tables err: " + err.Error())
	}

	chains, err := conn.ListChains()
	if err != nil {
		panic("list chains err: " + err.Error())
	}

	for i := range tables {
		t := tables[i]
		fmt.Printf("table: Name=%s, Use=%d, Flags=0x%X, Family=%s\n",
			t.Name, t.Use, t.Flags, family2str(t.Family))

		tOjbs, err := conn.GetObjects(t)
		if err != nil {
			panic("get objects err: " + err.Error())
		}
		for i := range tOjbs {
			namedCounter, ok := tOjbs[i].(*nftables.CounterObj)
			if !ok {
				continue
			}
			fmt.Printf("  counter: Name=%s, Bytes=%d, Packets=%d\n",
				namedCounter.Name, namedCounter.Bytes, namedCounter.Packets)
		}

		sets, err := conn.GetSets(t)
		if err != nil {
			panic("get sets err: " + err.Error())
		}

		setMapping := make(map[string]*nftables.Set)
		setElements := make(map[string][]nftables.SetElement)
		for _, set := range sets {
			fmt.Printf("  Set{ID:%d, Name:%s, Anonymous:%v, Constant:%v, Interval:%v, IsMap:%v, HasTimeout:%v, Counter:%v, Dynamic:%v, Concatenation:%v, Timeout:%v, KeyType:%s, DataType:%s}\n",
				set.ID, set.Name, set.Anonymous, set.Constant, set.Interval, set.IsMap, set.HasTimeout, set.Counter, set.Dynamic, set.Concatenation, set.Timeout, set.KeyType.Name, set.DataType.Name)
			elements, err := conn.GetSetElements(set)
			if err != nil {
				panic("get set elements err: " + err.Error())
			}
			setElements[set.Name] = elements
			setMapping[set.Name] = set
		}

		for i := range chains {
			c := chains[i]
			if c.Table.Name == t.Name && (c.Name == "INGRESS-INPUT" || c.Name == "INGRESS-INPUT-sg-dmy1") {
				fmt.Printf("  chain: Name=%s, Handle=%d\n", c.Name, c.Handle)

				rules, err := conn.GetRules(t, c)
				if err != nil {
					fmt.Printf("  get rules [table: %s, chain: %s] err: %v\n", t.Name, c.Name, err)
					continue
				}

				for i := range rules {
					r, err := nl2rule(context.Background(), rules[i], setMapping, setElements)
					if err != nil {
						fmt.Printf("parsing nl rule error: %v", err)
					}
					fmt.Println(r.String())
					fmt.Println("**********************************************************")
				}

			}
		}

	}
}
