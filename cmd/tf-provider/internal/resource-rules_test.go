package internal

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_isPortRangesValid(t *testing.T) {
	type tc struct {
		src   string
		valid bool
	}
	cases := []tc{
		{"", false},
		{" ", false},
		{" 10 ", true},
		{" 10-15 ", true},
		{" 10  - 15 10 ", true},
		{" 10  - 15 10-12 ", true},
		{" 1 10  - 15 10 12 ", true},
		{" 10  - 15 10 12 - ", false},
		{" - 10  - 15 10 12  ", false},
	}
	for i, c := range cases {
		v := isPortRangesValid(c.src)
		require.Equalf(t, c.valid, v, "test-on %v: '%s'", i, c.src)
	}
}

func Test_parsePorts(t *testing.T) {
	type rng = [2]uint16
	type tc struct {
		src    string
		failed bool
		r      []rng
	}
	cases := []tc{
		{"11", false, []rng{{11, 11}}},
		{"11-12", false, []rng{{11, 12}}},
		{"11 11-12", false, []rng{{11, 11}, {11, 12}}},
		{"9999999 ", true, nil},
	}
	for i, c := range cases {
		var rr []rng
		err := parsePorts(c.src, func(start, end uint16) error {
			rr = append(rr, rng{start, end})
			return nil
		})
		require.Equalf(t, c.failed, err != nil, "test-on %v: '%s'", i, c.src)
		if err == nil {
			require.Equalf(t, c.r, rr, "test-on %v: '%s'", i, c.src)
		}
	}
}
