package fixtures

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_NetworksFixtures_Example(t *testing.T) {
	var res NetworksRC
	e := res.LoadFixture("sample-fixture.yaml")
	require.NoError(t, e)
	x := bytes.NewBuffer(nil)
	e = res.TfRcConf(x)
	require.NoError(t, e)
	require.NotEmpty(t, x.Bytes())
}
