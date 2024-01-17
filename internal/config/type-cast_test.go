package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_typeCastFunc(t *testing.T) {
	type (
		ss   string
		ii32 int32
		ii   int
		tt   time.Time
		dd   time.Duration
	)

	data := [...]func() error{
		new(typeCastFunc[int]).load,
		new(typeCastFunc[uint]).load,
		new(typeCastFunc[int64]).load,
		new(typeCastFunc[uint64]).load,
		new(typeCastFunc[int32]).load,
		new(typeCastFunc[uint32]).load,
		new(typeCastFunc[int16]).load,
		new(typeCastFunc[uint16]).load,
		new(typeCastFunc[int8]).load,
		new(typeCastFunc[uint8]).load,
		new(typeCastFunc[float32]).load,
		new(typeCastFunc[float64]).load,
		new(typeCastFunc[string]).load,
		new(typeCastFunc[bool]).load,
		new(typeCastFunc[time.Time]).load,
		new(typeCastFunc[time.Duration]).load,
		new(typeCastFunc[ss]).load,
		new(typeCastFunc[tt]).load,
		new(typeCastFunc[dd]).load,
		new(typeCastFunc[ii]).load,
		new(typeCastFunc[ii32]).load,
	}
	for i := range data {
		assert.NoError(t, data[i]())
	}
	/*//
	assert.ErrorIs(t,
		new(typeCastFunc[struct{ a int }]).load(),
		ErrTypeCastNotSupported)
	*/
}
