package queue

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_FIFO(t *testing.T) {
	f := NewFIFO[any]()
	r := f.Reader()
	rd := func() (ret any) {
		select {
		case ret = <-r:
		case <-time.After(time.Second):
		}
		return ret
	}
	var exp []any
	var got []any
	exp = append(exp, 1, 2, "3")
	ok := f.Put(exp...)
	require.True(t, ok)
	got = append(got, rd(), rd(), rd())
	require.Equal(t, exp, got)
	go func() {
		for {
			_ = f.Put(1)
		}
	}()
	go func() {
		for {
			<-r
		}
	}()
	time.Sleep(101 * time.Millisecond)
	_ = f.Close()
	ok = f.Put(1)
	require.False(t, ok)
}
