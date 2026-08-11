package icmp

import (
	"strings"

	"github.com/v-byte-cpu/sx/pkg/scan"
)

// Set to typical maximum Ethernet frame size = MTU (1500 bytes)
// + Ethernet header (14 bytes) + FCS (4 bytes)
const MaxPacketLength = 1518

func BPFFilter(r *scan.Range) (filter string, maxPacketLength int) {
	var sb strings.Builder
	if r.SrcIP.Is6() || (r.DstPrefix.IsValid() && r.DstPrefix.Addr().Is6()) {
		sb.WriteString("icmp6 and icmp6[0]!=128")
		if r.DstPrefix.IsValid() {
			sb.WriteString(" and ip6 src net ")
			sb.WriteString(r.DstPrefix.String())
		}
		return sb.String(), MaxPacketLength
	}
	// filter ECHO requests
	sb.WriteString("icmp and icmp[0]!=8")
	if r.DstPrefix.IsValid() {
		sb.WriteString(" and ip src net ")
		sb.WriteString(r.DstPrefix.String())
	}
	return sb.String(), MaxPacketLength
}
