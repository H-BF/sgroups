package errors

import (
	"encoding/json"

	"github.com/H-BF/corlib/pkg/jsonview"
)

// ErrDetails details error
type ErrDetails struct {
	Reason  error
	API     string
	Msg     string
	Details interface{}
}

// Cause supports errors package
func (e ErrDetails) Cause() error {
	return e.Reason
}

// Error impl 'error'
func (e ErrDetails) Error() string {
	if e.Reason == nil {
		return ""
	}
	b, err := e.MarshalJSON()
	if err != nil {
		return "<?>"
	}
	b1 := b[:0]
	for i := range b {
		switch b[i] {
		case '"':
			b1 = append(b1, '\'')
		case '\\':
		default:
			b1 = append(b1, b[i])
		}
	}
	return string(b)
}

// MarshalJSON impl 'json.Marshaler'
func (e ErrDetails) MarshalJSON() ([]byte, error) {
	if e.Reason == nil {
		return nil, nil
	}
	obj := struct {
		A string         `json:"api,omitempty"`
		B string         `json:"msg,omitempty"`
		R string         `json:"reason,omitempty"`
		C json.Marshaler `json:"details,omitempty"`
	}{
		A: e.API,
		B: e.Msg,
		R: e.Reason.Error(),
		C: jsonview.Marshaler(e.Details),
	}
	return json.Marshal(obj)
}
