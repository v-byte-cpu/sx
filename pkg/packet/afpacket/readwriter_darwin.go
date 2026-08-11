package afpacket

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/v-byte-cpu/sx/pkg/packet"
)

const (
	defaultSnapLen = 262144
	loopbackLen    = 4
)

var (
	ErrUnsupportedLinkType = errors.New("unsupported pcap link type")
	errShortLoopbackPacket = errors.New("short loopback packet")
)

type packetHandle interface {
	Close()
	LinkType() layers.LinkType
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	SetBPFFilter(string) error
	WritePacketData([]byte) error
}

type packetLinkMode int

const (
	packetLinkEthernet packetLinkMode = iota
	packetLinkRaw
	packetLinkNull
	packetLinkLoop
)

type Source struct {
	handle packetHandle
	mode   packetLinkMode
	ipv6   bool
}

// Assert that Source conforms to the packet.ReadWriter interface.
var _ packet.ReadWriter = (*Source)(nil)

func NewPacketSource(iface string, vpnMode bool, ipv6 bool) (*Source, error) {
	handle, err := pcap.OpenLive(iface, defaultSnapLen, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	if err = handle.SetDirection(pcap.DirectionIn); err != nil {
		handle.Close()
		return nil, err
	}
	return newSource(handle, vpnMode, ipv6)
}

func newSource(handle packetHandle, vpnMode bool, ipv6 bool) (*Source, error) {
	mode, err := newPacketLinkMode(handle.LinkType(), vpnMode, ipv6)
	if err != nil {
		handle.Close()
		return nil, err
	}
	return &Source{handle: handle, mode: mode, ipv6: ipv6}, nil
}

func newPacketLinkMode(linkType layers.LinkType, vpnMode bool, ipv6 bool) (packetLinkMode, error) {
	if !vpnMode {
		if linkType == layers.LinkTypeEthernet {
			return packetLinkEthernet, nil
		}
		return 0, fmt.Errorf("%w: %s", ErrUnsupportedLinkType, linkType)
	}

	switch linkType {
	case layers.LinkTypeRaw:
		return packetLinkRaw, nil
	case layers.LinkTypeIPv4:
		if !ipv6 {
			return packetLinkRaw, nil
		}
	case layers.LinkTypeIPv6:
		if ipv6 {
			return packetLinkRaw, nil
		}
	case layers.LinkTypeNull:
		return packetLinkNull, nil
	case layers.LinkTypeLoop:
		return packetLinkLoop, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrUnsupportedLinkType, linkType)
	}
	return 0, fmt.Errorf("%w: %s", ErrUnsupportedLinkType, linkType)
}

func (s *Source) SetBPFFilter(bpfFilter string, _ int) error {
	return s.handle.SetBPFFilter(bpfFilter)
}

func (s *Source) Close() {
	s.handle.Close()
}

func (s *Source) ReadPacketData() ([]byte, *gopacket.CaptureInfo, error) {
	data, ci, err := s.handle.ReadPacketData()
	if err != nil {
		return nil, nil, err
	}
	data, err = s.decodePacket(data)
	if err != nil {
		return nil, nil, err
	}
	ci.CaptureLength = len(data)
	ci.Length = len(data)
	return data, &ci, nil
}

func (s *Source) decodePacket(data []byte) ([]byte, error) {
	switch s.mode {
	case packetLinkNull, packetLinkLoop:
		if len(data) < loopbackLen {
			return nil, errShortLoopbackPacket
		}
		return data[loopbackLen:], nil
	default:
		return data, nil
	}
}

func (s *Source) WritePacketData(pkt []byte) error {
	return s.handle.WritePacketData(s.encodePacket(pkt))
}

func (s *Source) encodePacket(pkt []byte) []byte {
	switch s.mode {
	case packetLinkNull:
		return appendLoopbackHeaderForFamily(pkt, binary.LittleEndian, s.ipv6)
	case packetLinkLoop:
		return appendLoopbackHeaderForFamily(pkt, binary.BigEndian, s.ipv6)
	default:
		return pkt
	}
}

func appendLoopbackHeaderForFamily(pkt []byte, byteOrder binary.ByteOrder, ipv6 bool) []byte {
	result := make([]byte, loopbackLen+len(pkt))
	family := layers.ProtocolFamilyIPv4
	if ipv6 {
		family = layers.ProtocolFamilyIPv6Darwin
	}
	byteOrder.PutUint32(result[:loopbackLen], uint32(family))
	copy(result[loopbackLen:], pkt)
	return result
}
