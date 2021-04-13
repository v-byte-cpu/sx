package tcp

import (
	"fmt"
	"strings"

	"github.com/v-byte-cpu/sx/pkg/scan"
)

// Set to typical maximum Ethernet frame size = MTU (1500 bytes)
// + Ethernet header (14 bytes) + FCS (4 bytes)
const MaxPacketLength = 1518

func BPFFilter(r *scan.Range) (filter string, maxPacketLength int) {
	var sb strings.Builder
	sb.WriteString("tcp")
	if r.DstSubnet != nil {
		sb.WriteString(" and ip src net ")
		sb.WriteString(r.DstSubnet.String())
	}
	if len(r.Ports) > 0 {
		sb.WriteString(" and (")
		var ranges []string
		for _, pr := range r.Ports {
			ranges = append(ranges, fmt.Sprintf("src portrange %d-%d", pr.StartPort, pr.EndPort))
		}
		sb.WriteString(strings.Join(ranges, " or "))
		sb.WriteRune(')')
	}
	return sb.String(), MaxPacketLength
}

func SYNACKBPFFilter(r *scan.Range) (filter string, maxPacketLength int) {
	filter, maxPacketLength = BPFFilter(r)
	return filter + " and tcp[13] == 18", maxPacketLength
}
