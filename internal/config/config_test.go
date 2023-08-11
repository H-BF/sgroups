package config

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/H-BF/corlib/pkg/functional"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_FromDefaultValuesConf(t *testing.T) {
	const (
		b  ValueT[bool]          = "values/bool"
		s  ValueT[string]        = "values/string"
		ti ValueT[time.Time]     = "values/time"
		du ValueT[time.Duration] = "values/duration"
		i  ValueT[int]           = "values/int"
		u  ValueT[uint]          = "values/uint"
		f  ValueT[float32]       = "values/float"
	)

	expected := map[string]interface{}{
		b.String():  true,
		s.String():  "string",
		ti.String(): time.Now(),
		du.String(): time.Minute,
		i.String():  int(1),
		u.String():  uint(1),
		f.String():  float32(1.0),
	}

	opts := make([]Option, 0, len(expected))
	for k, v := range expected {
		opts = append(opts, WithDefValue{Key: k, Val: v})
	}
	err := InitGlobalConfig(opts...)
	require.NoError(t, err)

	ctx := context.TODO()
	for k, v := range expected {
		g := String2ValueT[interface{}](k)
		v1, e := g.Value(ctx)
		require.NoError(t, e)
		require.Equal(t, v, v1)
	}

	invokers := map[string]interface{}{
		b.String():  b.Value,
		s.String():  s.Value,
		ti.String(): ti.Value,
		du.String(): du.Value,
		i.String():  i.Value,
		u.String():  u.Value,
		f.String():  f.Value,
	}

	for k, inv := range invokers {
		invoker := functional.MustCallableOf(inv)
		res, e := invoker.Invoke(ctx)
		require.NoError(t, e)
		if e, _ = res[1].(error); !assert.NoError(t, e) {
			return
		}
		require.Equal(t, expected[k], res[0])
	}
}

func Test_FromEnvConf(t *testing.T) {
	err := os.Setenv("TEST_VALUES_BOOL", "true")
	require.NoError(t, err)

	err = InitGlobalConfig(WithAcceptEnvironment{EnvPrefix: "TEST"})
	require.NoError(t, err)

	const (
		b ValueT[bool] = "values/bool"
	)
	var (
		rB  bool
		ctx = context.TODO()
	)
	rB, err = b.Value(ctx)
	require.NoError(t, err)
	assert.Equal(t, true, rB)
}

func Test_SourceConf(t *testing.T) {
	const data = `
values:
   bool: true
   duration: 1s
`

	err := InitGlobalConfig(WithSource{
		Source: bytes.NewBuffer([]byte(data)),
		Type:   "yaml",
	})

	if !assert.NoError(t, err) {
		return
	}
	const (
		b  ValueT[bool]          = "values/bool"
		du ValueT[time.Duration] = "values/duration"
	)
	ctx := context.TODO()
	_, err = b.Value(ctx)
	require.NoError(t, err)
	_, err = du.Value(ctx)
	assert.NoError(t, err)
}

func Test_NetCIDR_Json(t *testing.T) {
	_, n1, e1 := net.ParseCIDR("192.168.1.0/24")
	require.NoError(t, e1)
	_, n2, e2 := net.ParseCIDR("192.168.2.0/24")
	require.NoError(t, e2)
	ar := []NetCIDR{{n1}, {n2}}
	b, e3 := json.Marshal(ar)
	require.NoError(t, e3)
	var ar2 []NetCIDR
	e4 := json.Unmarshal(b, &ar2)
	require.NoError(t, e4)
	require.Equal(t, ar, ar2)
}

/*//
func Test_S(t *testing.T) {


	data := `
logger:
  level: INFO

trace:
  enable: true

metrics:
  enable: true

api-server:
  endpoint: tcp://127.0.0.1:9001
  graceful-shutdown: 30s

`

	err := InitGlobalConfig(WithSource{
		Source: bytes.NewBuffer([]byte(data)),
		Type:   "yaml",
	})

	if !assert.NoError(t, err) {
		return
	}

	const a ValueDuration = "grpc/servers/graceful-shutdown"
	//const a1 ValueString = "services/.0.announcer/endpoint"
	const a1 ValueString = "services/0/announcer/endpoint"
	var b time.Duration

	b, err = a.Maybe(context.Background())
	if !assert.NoError(t, err) {
		return
	}

	var b1 string
	b1, err = a1.Maybe(context.Background())
	if !assert.NoError(t, err) {
		return
	}

	_ = b1
	b += 0

}
*/
