package pg

import (
	"io"
)

type writer struct {
	io.Writer
}

// WriteByte -
func (w *writer) WriteByte(c byte) (int, error) {
	return w.Writer.Write([]byte{c})
}

// WriteString -
func (w *writer) WriteString(s string) (int, error) {
	return w.Writer.Write([]byte(s))
}
