package config

import (
	"encoding/json"

	"github.com/pkg/errors"
)

func typeCastSliceT[T any](data any) ([]T, error) {
	var ret []T
	var err error
	switch v := data.(type) {
	case []byte:
		err = json.Unmarshal(v, &ret)
	case string:
		err = json.Unmarshal([]byte(v), &ret)
	case []T:
		ret = v
	case *[]T:
		ret = *v
	default:
		if b, e := json.Marshal(data); e == nil {
			err = json.Unmarshal(b, &ret)
			if err != nil {
				err = errors.Errorf("unable cast %#v to type %T type", data, ret)
			}
		}
	}
	return ret, err
}
