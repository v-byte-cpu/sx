package arp

import (
	"fmt"

	"github.com/v-byte-cpu/sx/pkg/scan"
)

// For ARP packets:
// Ethernet header (14 bytes) + ARP packet (28 bytes) + FCS (4 bytes) = 46 bytes
// So it is less than Ethernet minimum frame size = 64 bytes
const MaxPacketLength = 64

func BPFFilter(r *scan.Range) (filter string, maxPacketLength int) {
	if r.Subnet == nil {
		return "arp", MaxPacketLength
	}
	return fmt.Sprintf("arp src net %s", r.Subnet.String()), MaxPacketLength
}
