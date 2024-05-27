package hlp

const (
	// OffsetSAddrV4 is offset of source addr in IPv4 packet
	OffsetSAddrV4 uint32 = 12
	// OffsetDAddrV4 is offset of destination addr in IPv4 packet
	OffsetDAddrV4 uint32 = 16
	// OffsetSAddrV6 is offset of source addr in IPv6 packet
	OffsetSAddrV6 uint32 = 8
	// OffsetDAddrV6 is offset of destination addr in IPv6 packet
	OffsetDAddrV6 uint32 = 24
)

const (
	// OffsetSPort is offset of source port in packet
	OffsetSPort = 0
	// OffsetDPort is offset of destination port in packet
	OffsetDPort = 2
)
