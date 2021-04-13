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
	// filter ECHO requests
	sb.WriteString("icmp and icmp[0]!=8")
	if r.DstSubnet != nil {
		sb.WriteString(" and ip src net ")
		sb.WriteString(r.DstSubnet.String())
	}
	return sb.String(), MaxPacketLength
}
