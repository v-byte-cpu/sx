package ndp

import (
	"fmt"

	"github.com/v-byte-cpu/sx/pkg/scan"
)

const MaxPacketLength = 1518

func BPFFilter(r *scan.Range) (string, int) {
	filter := "icmp6 and icmp6[0] == 136"
	if r.DstPrefix.IsValid() {
		filter = fmt.Sprintf("%s and src net %s", filter, r.DstPrefix)
	}
	return filter, MaxPacketLength
}
