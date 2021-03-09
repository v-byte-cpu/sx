//go:generate mockgen -destination=mock_sender_test.go -package=packet -source sender.go

package packet

import (
	"context"

	"github.com/google/gopacket"
)

type BufferData struct {
	Buf gopacket.SerializeBuffer
	Err error
}

type Sender interface {
	SendPackets(ctx context.Context, in <-chan *BufferData) (done <-chan interface{}, errc <-chan error)
}

type Writer interface {
	WritePacketData(pkt []byte) error
}

type sender struct {
	w Writer
}

func NewSender(w Writer) Sender {
	return &sender{w}
}

func (s *sender) SendPackets(ctx context.Context, in <-chan *BufferData) (<-chan interface{}, <-chan error) {
	done := make(chan interface{})
	errc := make(chan error, 100)
	go func() {
		defer func() {
			close(done)
			close(errc)
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-in:
				if !ok {
					return
				}
				if pkt.Err != nil {
					errc <- pkt.Err
					continue
				}
				if err := s.w.WritePacketData(pkt.Buf.Bytes()); err != nil {
					errc <- err
				}
			}
		}
	}()
	return done, errc
}
