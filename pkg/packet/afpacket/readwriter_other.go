//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd
// +build !linux,!darwin,!dragonfly,!freebsd,!netbsd,!openbsd

package afpacket

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/v-byte-cpu/sx/pkg/packet"
)

var ErrOS = errors.New("afpacket is not supported on your OS platform")

type Source struct{}

// Assert that AfPacketSource conforms to the packet.ReadWriter interface
var _ packet.ReadWriter = (*Source)(nil)

func NewPacketSource(iface string, vpnMode bool) (*Source, error) {
	return nil, ErrOS
}

func (s *Source) SetBPFFilter(bpfFilter string, maxPacketLength int) error {
	return ErrOS
}

func (s *Source) Close() {}

func (s *Source) ReadPacketData() (data []byte, info *gopacket.CaptureInfo, err error) {
	err = ErrOS
	return
}

func (s *Source) WritePacketData(pkt []byte) error {
	return ErrOS
}
