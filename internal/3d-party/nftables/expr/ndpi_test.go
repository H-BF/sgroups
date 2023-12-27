package expr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

/*//TODO:     Тесты - П Е Р Е Д Е Л А Т Ь
1 - каждый тест не должен иметь состояний влияющих на другой тест
2 - нету тестов на marshal/unmarshal
3 - if !assert.Error(suite.T(), err) {
		suite.T().FailNow()
		return false
	} <-- вместо этой конструкции нужно использовать sui.Require().NoError(err)
*/

type ndpiTestSuite struct {
	suite.Suite
}

func (sui *ndpiTestSuite) SetupTest() {
	NdpiModuleProtocolsFile = "./test-data/ndpi-info.txt"
	NdpiState = ndpiLoadInternal()
	sui.Require().NoError(NdpiState.FailReason) //TODO: Это сразу отсанавливает выполнение если что не так
}

func (sui *ndpiTestSuite) proto2InvalidBitmask(expMask ndpiProtoBitmask) bool {
	var err error
	suite.mask, err = suite.ndpi.protocolsToBitmask()
	if !assert.Error(suite.T(), err) {
		suite.T().FailNow()
		return false
	}

	return assert.Equal(suite.T(), expMask, suite.mask)
}

func (sui *ndpiTestSuite) proto2ValidBitmask(expMask ndpiProtoBitmask) bool {
	var err error
	suite.mask, err = suite.ndpi.protocolsToBitmask()
	if !assert.NoError(suite.T(), err) {
		suite.T().FailNow()
		return false
	}

	return assert.Equal(suite.T(), expMask, suite.mask)
}

func (sui *ndpiTestSuite) bitmask2Proto(expProtos []string) bool {
	suite.ndpi.Protocols = nil
	sui.ndpi.poplulateProtocols(suite.mask)
	return assert.Equal(suite.T(), expProtos, suite.ndpi.Protocols)
}

func (sui *ndpiTestSuite) Test_NdpiUnSupportedProtocols() {
	suite.ndpi.Protocols = []string{"memcached", "signal", "xbox", "modbus", "whatsappcall"}
	ok := sui.proto2InvalidBitmask(ndpiProtoBitmask{})
	if !ok {
		return
	}
	sui.bitmask2Proto(nil)
}

func (suite *ndpiTestSuite) Test_NdpiOneSupportedProtocol() {
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

func (sui *ndpiTestSuite) Test_NdpiSubstractionProtocols() {
	suite.ndpi.Protocols = []string{"http", "-http"}

	ok := suite.proto2ValidBitmask(ndpiProtoBitmask{})
	if !ok {
		return
	}
	suite.bitmask2Proto(nil)
}

func (sui *ndpiTestSuite) Test_NdpiDublicatedProtocols() {
	suite.ndpi.Protocols = []string{"http", "http", "http"}
	expMask := ndpiProtoBitmask{
		fds_bits: [NDPI_NUM_FDS_BITS]ndpiMaskType{
			0: 0x80,
		},
	}
	ok := sui.proto2ValidBitmask(expMask)
	if !ok {
		return
	}
	sui.bitmask2Proto([]string{"http"})
}

func (sui *ndpiTestSuite) Test_NdpiSeveralSuportedProtocols() {
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
	ok := sui.proto2ValidBitmask(expMask)
	if !ok {
		return
	}
	//reordered according to bitmask
	sui.bitmask2Proto([]string{
		NdpiState.Protocols.numbit2ProtoName[2],
		NdpiState.Protocols.numbit2ProtoName[5],
		NdpiState.Protocols.numbit2ProtoName[7],
		NdpiState.Protocols.numbit2ProtoName[9],
	})
}

func Test_NDPI(t *testing.T) {
	suite.Run(t, new(ndpiTestSuite))
}
