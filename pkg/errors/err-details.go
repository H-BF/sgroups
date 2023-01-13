package errors

import (
	"encoding/json"

	"github.com/H-BF/corlib/pkg/jsonview"
)

// ErrDetails details error
type ErrDetails struct {
	Api     string
	Msg     string
	Details interface{}
}

// Error impl 'error'
func (e ErrDetails) Error() string {
	b, err := e.MarshalJSON()
	if err != nil {
		return "<?>"
	}
	return string(b)
}

// MarshalJSON impl 'json.Marshaler'
func (e ErrDetails) MarshalJSON() ([]byte, error) {
	obj := struct {
		A string         `json:"api,omitempty"`
		B string         `json:"msg,omitempty"`
		C json.Marshaler `json:"details,omitempty"`
	}{
		A: e.Api,
		B: e.Msg,
		C: jsonview.Marshaler(e.Details),
	}
	return json.Marshal(obj)
}
