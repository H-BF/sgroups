package expr

import (
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/suite"
)

type ndpiTestSuite struct {
	suite.Suite
}

func (sui *ndpiTestSuite) SetupTest() {
	NdpiModuleProtocolsFile = "./test-data/ndpi-info.txt"
	NdpiState = ndpiLoadInternal()
	sui.Require().NoError(NdpiState.FailReason)
}

func (sui *ndpiTestSuite) bitmask2Proto(mask *ndpiProtoBitmask, expProtos []string) {
	ndpi := Ndpi{
		Protocols: nil,
	}
	ndpi.poplulateProtocols(mask)
	sui.Require().Equal(expProtos, ndpi.Protocols)
}

func (sui *ndpiTestSuite) Test_NdpiUnSupportedProtocols() {
	protocols := []string{"memcached", "signal", "xbox", "modbus", "whatsappcall"}
	expMask := ndpiProtoBitmask{}
	ndpi := Ndpi{
		Protocols: protocols,
	}
	mask, err := ndpi.protocolsToBitmask()
	sui.Require().Error(err)
	if err == nil {
		return
	}
	sui.Require().Equal(expMask, mask)
	sui.bitmask2Proto(&mask, nil)
}

func (sui *ndpiTestSuite) Test_NdpiOneSupportedProtocol() {
	protocols := []string{"http"}
	expMask := ndpiProtoBitmask{
		fds_bits: [NDPI_NUM_FDS_BITS]ndpiMaskType{
			0: 0x80,
		},
	}
	ndpi := Ndpi{
		Protocols: protocols,
	}
	mask, err := ndpi.protocolsToBitmask()
	sui.Require().NoError(err)
	if err != nil {
		return
	}
	sui.Require().Equal(expMask, mask)
	sui.bitmask2Proto(&mask, protocols)
}

func (sui *ndpiTestSuite) Test_NdpiSubstractionProtocols() {
	protocols := []string{"http", "-http"}
	expMask := ndpiProtoBitmask{}
	ndpi := Ndpi{
		Protocols: protocols,
	}
	mask, err := ndpi.protocolsToBitmask()
	sui.Require().NoError(err)
	if err != nil {
		return
	}
	sui.Require().Equal(expMask, mask)
	sui.bitmask2Proto(&mask, nil)
}

func (sui *ndpiTestSuite) Test_NdpiDublicatedProtocols() {
	protocols := []string{"http", "http", "http"}
	expMask := ndpiProtoBitmask{
		fds_bits: [NDPI_NUM_FDS_BITS]ndpiMaskType{
			0: 0x80,
		},
	}
	ndpi := Ndpi{
		Protocols: protocols,
	}
	mask, err := ndpi.protocolsToBitmask()
	sui.Require().NoError(err)
	if err != nil {
		return
	}
	sui.Require().Equal(expMask, mask)
	sui.bitmask2Proto(&mask, protocols[:1])
}

func (sui *ndpiTestSuite) Test_NdpiSeveralSuportedProtocols() {
	protocols := []string{
		NdpiState.Protocols.numbit2ProtoName[7],
		NdpiState.Protocols.numbit2ProtoName[5],
		NdpiState.Protocols.numbit2ProtoName[2],
		NdpiState.Protocols.numbit2ProtoName[9]}

	expMask := ndpiProtoBitmask{
		fds_bits: [NDPI_NUM_FDS_BITS]ndpiMaskType{
			0: 0x2a4,
		},
	}
	ndpi := Ndpi{
		Protocols: protocols,
	}
	mask, err := ndpi.protocolsToBitmask()
	sui.Require().NoError(err)
	if err != nil {
		return
	}
	sui.Require().Equal(expMask, mask)
	//reordered according to bitmask
	sui.bitmask2Proto(&mask, []string{
		NdpiState.Protocols.numbit2ProtoName[2],
		NdpiState.Protocols.numbit2ProtoName[5],
		NdpiState.Protocols.numbit2ProtoName[7],
		NdpiState.Protocols.numbit2ProtoName[9],
	})
}

func (sui *ndpiTestSuite) Test_NdpiMixedProtocols() {
	protocols := []string{"http", "signal", "dns"}
	expMask := ndpiProtoBitmask{
		fds_bits: [NDPI_NUM_FDS_BITS]ndpiMaskType{
			0: 0x80,
		},
	}

	ndpi := Ndpi{
		Protocols: protocols,
	}

	mask, err := ndpi.protocolsToBitmask()
	sui.Require().Error(err)
	if err == nil {
		return
	}

	sui.Require().Equal(expMask, mask)
	sui.bitmask2Proto(&mask, protocols[:1])
}

func (sui *ndpiTestSuite) Test_NdpiMarshalHostOneProto() {
	expHost := "youtube"
	expProto := "http"
	ndpiExp, err := NewNdpi(NdpiWithHost(expHost), NdpiWithProtocols(expProto))
	sui.Require().NoError(err)
	m, err := ndpiExp.marshal(0)
	sui.Require().NoError(err)
	ndpi, err := NewNdpi()
	sui.Require().NoError(err)
	u, err := netlink.UnmarshalAttributes(m)
	sui.Require().NoError(err)
	err = ndpi.unmarshal(0, u[1].Data)
	sui.Require().NoError(err)
	sui.Require().Equal(ndpiExp, ndpi)

}

func (sui *ndpiTestSuite) Test_NdpiMarshalHostProtos() {
	expHost := "youtube"
	expProto := []string{"dns", "http"}
	ndpiExp, err := NewNdpi(NdpiWithHost(expHost), NdpiWithProtocols(expProto[0], expProto[1]))
	sui.Require().NoError(err)
	m, err := ndpiExp.marshal(0)
	sui.Require().NoError(err)
	ndpi, err := NewNdpi()
	sui.Require().NoError(err)
	u, err := netlink.UnmarshalAttributes(m)
	sui.Require().NoError(err)
	err = ndpi.unmarshal(0, u[1].Data)
	sui.Require().NoError(err)
	sui.Require().Equal(ndpiExp, ndpi)
}

func (sui *ndpiTestSuite) Test_NdpiMarshalRegex() {
	ndpiExp, err := NewNdpi(NdpiWithHost("/youtube/"), NdpiWithProtocols("http"))
	sui.Require().NoError(err)
	m, err := ndpiExp.marshal(0)
	sui.Require().NoError(err)
	ndpi, err := NewNdpi()
	sui.Require().NoError(err)
	u, err := netlink.UnmarshalAttributes(m)
	sui.Require().NoError(err)
	err = ndpi.unmarshal(0, u[1].Data)
	sui.Require().NoError(err)
	sui.Require().Equal(ndpiExp, ndpi)

}

func (sui *ndpiTestSuite) Test_NdpiMarshalHost() {

	ndpiExp, err := NewNdpi(NdpiWithHost("youtube"))
	sui.Require().NoError(err)
	m, err := ndpiExp.marshal(0)
	sui.Require().NoError(err)
	ndpi, err := NewNdpi()
	sui.Require().NoError(err)
	u, err := netlink.UnmarshalAttributes(m)
	sui.Require().NoError(err)
	err = ndpi.unmarshal(0, u[1].Data)
	sui.Require().NoError(err)
	sui.Require().Equal(ndpiExp, ndpi)
}

func Test_NDPI(t *testing.T) {
	suite.Run(t, new(ndpiTestSuite))
}
