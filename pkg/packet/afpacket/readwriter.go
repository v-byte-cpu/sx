package afpacket

import (
	"github.com/google/gopacket"
	afp "github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/v-byte-cpu/sx/pkg/packet"
	"golang.org/x/net/bpf"
)

type AfPacketSource struct {
	handle *afp.TPacket
}

// Assert that AfPacketSource conforms to the packet.ReadWriter interface
var _ packet.ReadWriter = (*AfPacketSource)(nil)

func NewPacketSource(iface string) (*AfPacketSource, error) {
	handle, err := afp.NewTPacket(afp.SocketRaw, afp.OptInterface(iface))
	if err != nil {
		return nil, err
	}
	return &AfPacketSource{handle}, nil
}

// maxPacketLength is the maximum size of packets to capture in bytes.
// pcap calls it "snaplen" and default value used in tcpdump is 262144 bytes,
// that is redundant for most scans, see pcap(3) and tcpdump(1) for more info
func (s *AfPacketSource) SetBPFFilter(bpfFilter string, maxPacketLength int) error {
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, maxPacketLength, bpfFilter)
	if err != nil {
		return err
	}
	bpfIns := make([]bpf.RawInstruction, 0, len(pcapBPF))
	for _, ins := range pcapBPF {
		rawIns := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
		bpfIns = append(bpfIns, rawIns)
	}
	return s.handle.SetBPF(bpfIns)
}

func (s *AfPacketSource) Close() {
	s.handle.Close()
}

func (s *AfPacketSource) ReadPacketData() ([]byte, *gopacket.CaptureInfo, error) {
	data, ci, err := s.handle.ZeroCopyReadPacketData()
	return data, &ci, err
}

func (s *AfPacketSource) WritePacketData(pkt []byte) error {
	return s.handle.WritePacketData(pkt)
}
