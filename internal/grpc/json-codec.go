package grpc

import (
	"fmt"

	"google.golang.org/grpc/encoding"
	jsonpb "google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// JsonCodecName -
const JsonCodecName = "json"

func init() {
	cod := jsonCodec{
		marshalOpts: jsonpb.MarshalOptions{
			EmitUnpopulated: true,
			AllowPartial:    true,
		},
		unmarshalOpts: jsonpb.UnmarshalOptions{
			AllowPartial: true,
		},
	}
	encoding.RegisterCodec(cod) //register 'grpc+json' codec
}

type jsonCodec struct {
	marshalOpts   jsonpb.MarshalOptions
	unmarshalOpts jsonpb.UnmarshalOptions
}

// Name - impl grpc/encoding.Codec
func (jsonCodec) Name() string {
	return JsonCodecName
}

// Marshal - impl grpc/encoding.Codec
func (c jsonCodec) Marshal(v interface{}) (out []byte, err error) {
	m, ok := v.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("grpc+json/Marshal: '%T' is not a 'proto.Message'", m)
	}
	return c.marshalOpts.Marshal(m)
}

// Unmarshal - impl grpc/encoding.Codec
func (c jsonCodec) Unmarshal(data []byte, v interface{}) (err error) {
	m, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("grpc+json/Unmarshal: '%T' is not a 'proto.Message'", m)
	}
	return c.unmarshalOpts.Unmarshal(data, m)
}

// https://github.com/johanbrandhorst/grpc-json-example
/*//                       cURL - EPAMPLE
#!/bin/bash
echo -en '\x00\x00\x00\x00\x02{}' | curl -X POST -k --http2-prior-knowledge \
        -H "Content-Type: application/grpc+json" \
        --data-binary @- \
        --output - \
        -v \
        http://127.0.0.1:9000/hbf.v1.sgroups.SecGroupService/SyncStatus
*/
