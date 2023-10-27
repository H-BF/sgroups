package fixtures

import (
	"context"
	"testing"

	domain "github.com/H-BF/sgroups/internal/models/sgroups"

	"github.com/stretchr/testify/require"
)

func Test_Load_AccTests(t *testing.T) {
	tc := AccTests{
		Ctx: context.Background(),
	}
	tc.LoadFixture(t, "sample-acc-test.yaml")
	pp := tc.InitialBackend.Networks.Decode()
	var dd DomainRcList[domain.Network]
	Backend2Domain(pp, &dd)
	di := dd.ToDict()
	_ = tc
	_ = pp
	_ = dd
	_ = di
	i := 1
	i++
	//TODO: дополнить тест
}

func Test_ExtractKey(t *testing.T) {
	var m domain.Network
	m.Name = "123"
	s := extractKey(m)
	require.Equal(t, m.Name, s)
	//TODO: дополнить тест
}
