package patterns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Path(t *testing.T) {
	type item struct {
		src   string
		valid bool
	}
	cases := [...]item{
		{"", true},
		{" ", false},
		{".", false},
		{"..", false},
		{"...", false},
		{".../", false},
		{"/.../", false},
		{"/.x../", true},
		{".x../", true},
		{"/", true},
		{"a", true},
		{" a", false},
		{"a ", false},
		{"/a", true},
		{"a/", true},
		{"/a/", true},
		{"a/b", true},
		{"/a/b", true},
		{"a/b/", true},
		{"a//b/", false},
		{`a/\b/`, false},
	}
	for i := range cases {
		c := cases[i]
		var p Path
		e := p.Set(c.src)
		f := require.Errorf
		if c.valid {
			f = require.NoErrorf
		}
		f(t, e, "fail-item #%v -> '%s'", i, c.src)
	}

	var p Path
	require.NoError(t, p.Set("a/b/c/"))
	require.Equal(t, "a/b/c", p.String())
}
