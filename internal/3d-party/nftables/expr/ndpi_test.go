package expr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TestNftNdpi struct {
	suite.Suite
	ndpi Ndpi
	mask ndpiProtoBitmask
}

func (suite *TestNftNdpi) SetupTest() {
	suite.ndpi.Protocols = nil
	NdpiState = ndpiModuleState{
		FailReason: nil,
		Protocols: struct {
			Supported        map[string]ndpiMaskType
			numbit2ProtoName [NDPI_NUM_BITS]string
			Disabled         map[string]bool
		}{
			Supported: map[string]ndpiMaskType{
				"unknown":     0,
				"ftp_control": 1,
				"pop3":        2,
				"smtp":        3,
				"imap":        4,
				"dns":         5,
				"ipp":         6,
				"http":        7,
				"mdns":        8,
				"ntp":         9,
				"netbios":     10,
			},
			numbit2ProtoName: [NDPI_NUM_BITS]string{
				"unknown",
				"ftp_control",
				"pop3",
				"smtp",
				"imap",
				"dns",
				"ipp",
				"http",
				"mdns",
				"ntp",
				"netbios",
			},
			Disabled: map[string]bool{
				"signal":       true,
				"memcached":    true,
				"smbv23":       true,
				"mining":       true,
				"nestlogsink":  true,
				"modbus":       true,
				"whatsappcall": true,
				"datasaver":    true,
				"xbox":         true,
				"qq":           true,
			},
		},
	}
}

func (suite *TestNftNdpi) proto2InvalidBitmask(expMask ndpiProtoBitmask) bool {
	var err error
	suite.mask, err = suite.ndpi.protocolsToBitmask()
	if !assert.Error(suite.T(), err) {
		suite.T().FailNow()
		return false
	}

	return assert.Equal(suite.T(), expMask, suite.mask)
}

func (suite *TestNftNdpi) proto2ValidBitmask(expMask ndpiProtoBitmask) bool {
	var err error
	suite.mask, err = suite.ndpi.protocolsToBitmask()
	if !assert.NoError(suite.T(), err) {
		suite.T().FailNow()
		return false
	}

	return assert.Equal(suite.T(), expMask, suite.mask)
}

func (suite *TestNftNdpi) bitmask2Proto(expProtos []string) bool {
	suite.ndpi.Protocols = nil
	suite.ndpi.poplulateProtocols(suite.mask)
	return assert.Equal(suite.T(), expProtos, suite.ndpi.Protocols)
}

func (suite *TestNftNdpi) Test_NdpiUnSupportedProtocols() {
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

func (suite *TestNftNdpi) Test_NdpiSubstractionProtocols() {
	suite.ndpi.Protocols = []string{"http", "-http"}

	ok := suite.proto2ValidBitmask(ndpiProtoBitmask{})
	if !ok {
		return
	}
	suite.bitmask2Proto(nil)
}

func (suite *TestNftNdpi) Test_NdpiDublicatedProtocols() {
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

func (suite *TestNftNdpi) Test_NdpiSeveralSuportedProtocols() {
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
