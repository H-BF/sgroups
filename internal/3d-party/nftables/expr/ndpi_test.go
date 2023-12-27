package expr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestNftNdpi struct {
	suite.Suite
}

func (sui *TestNftNdpi) SetupTest() {
	NdpiModuleProtocolsFile = "./test-data/ndpi-info.txt"
	NdpiState = ndpiLoadInternal()

}

func (sui *TestNftNdpi) proto2InvalidBitmask(expMask ndpiProtoBitmask) bool {
	var err error
	suite.mask, err = suite.ndpi.protocolsToBitmask()
	if !assert.Error(suite.T(), err) {
		suite.T().FailNow()
		return false
	}

	return assert.Equal(suite.T(), expMask, suite.mask)
}

func (sui *TestNftNdpi) proto2ValidBitmask(expMask ndpiProtoBitmask) bool {
	var err error
	suite.mask, err = suite.ndpi.protocolsToBitmask()
	if !assert.NoError(suite.T(), err) {
		suite.T().FailNow()
		return false
	}

	return assert.Equal(suite.T(), expMask, suite.mask)
}

func (sui *TestNftNdpi) bitmask2Proto(expProtos []string) bool {
	suite.ndpi.Protocols = nil
	suite.ndpi.poplulateProtocols(suite.mask)
	return assert.Equal(suite.T(), expProtos, suite.ndpi.Protocols)
}

func (sui *TestNftNdpi) Test_NdpiUnSupportedProtocols() {
	suite.ndpi.Protocols = []string{"memcached", "signal", "xbox", "modbus", "whatsappcall"}
	ok := suite.proto2InvalidBitmask(ndpiProtoBitmask{})
	if !ok {
		return
	}
	suite.bitmask2Proto(nil)
}

func (suite *TestNftNdpi) Test_NdpiOneSupportedProtocol() {
	suite.ndpi.Protocols = []string{"http"}
	expMask := ndpiProtoBitmask{
		fds_bits: [NDPI_NUM_FDS_BITS]ndpiMaskType{
			0: 0x80,
		},
	}
	ok := suite.proto2ValidBitmask(expMask)
	if !ok {
		return
	}
	suite.bitmask2Proto([]string{"http"})
}

func (sui *TestNftNdpi) Test_NdpiSubstractionProtocols() {
	suite.ndpi.Protocols = []string{"http", "-http"}

	ok := suite.proto2ValidBitmask(ndpiProtoBitmask{})
	if !ok {
		return
	}
	suite.bitmask2Proto(nil)
}

func (sui *TestNftNdpi) Test_NdpiDublicatedProtocols() {
	suite.ndpi.Protocols = []string{"http", "http", "http"}
	expMask := ndpiProtoBitmask{
		fds_bits: [NDPI_NUM_FDS_BITS]ndpiMaskType{
			0: 0x80,
		},
	}
	ok := suite.proto2ValidBitmask(expMask)
	if !ok {
		return
	}
	suite.bitmask2Proto([]string{"http"})
}

func (sui *TestNftNdpi) Test_NdpiSeveralSuportedProtocols() {
	suite.ndpi.Protocols = []string{
		NdpiState.Protocols.numbit2ProtoName[7],
		NdpiState.Protocols.numbit2ProtoName[5],
		NdpiState.Protocols.numbit2ProtoName[2],
		NdpiState.Protocols.numbit2ProtoName[9]}

	expMask := ndpiProtoBitmask{
		fds_bits: [NDPI_NUM_FDS_BITS]ndpiMaskType{
			0: 0x2a4,
		},
	}
	ok := suite.proto2ValidBitmask(expMask)
	if !ok {
		return
	}
	//reordered according to bitmask
	suite.bitmask2Proto([]string{
		NdpiState.Protocols.numbit2ProtoName[2],
		NdpiState.Protocols.numbit2ProtoName[5],
		NdpiState.Protocols.numbit2ProtoName[7],
		NdpiState.Protocols.numbit2ProtoName[9],
	})
}

func TestNftNdpiRun(t *testing.T) {
	suite.Run(t, new(TestNftNdpi))
}
