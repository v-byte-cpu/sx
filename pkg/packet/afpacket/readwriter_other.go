//go:build !linux && !darwin

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

func NewPacketSource(_ string, _ bool) (*Source, error) {
	return nil, ErrOS
}

func (*Source) SetBPFFilter(_ string, _ int) error {
	return ErrOS
}

func (*Source) Close() {}

func (*Source) ReadPacketData() (data []byte, info *gopacket.CaptureInfo, err error) {
	err = ErrOS
	return
}

func (*Source) WritePacketData(_ []byte) error {
	return ErrOS
}
