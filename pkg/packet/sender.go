//go:generate go tool mockgen -destination=mock_sender_test.go -package=packet -source sender.go

package packet

import (
	"context"

	"github.com/google/gopacket"
)

type BufferData struct {
	Buf gopacket.SerializeBuffer
	Err error
}

// Sender writes serialized packets.
type Sender interface {
	// SendPackets writes every packet from in until completion or context cancellation.
	SendPackets(ctx context.Context, in <-chan *BufferData) (done <-chan struct{}, errc <-chan error)
}

type Writer interface {
	WritePacketData(pkt []byte) error
}

func NewSender(w Writer) Sender {
	return &sender{w}
}

type sender struct {
	w Writer
}

func (s *sender) SendPackets(ctx context.Context, in <-chan *BufferData) (<-chan struct{}, <-chan error) {
	done := make(chan struct{})
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
				if !s.sendPacket(ctx, errc, pkt) {
					return
				}
			}
		}
	}()
	return done, errc
}

func (s *sender) sendPacket(ctx context.Context, errc chan<- error, pkt *BufferData) bool {
	if pkt.Err != nil {
		return sendError(ctx, errc, pkt.Err)
	}
	if err := s.w.WritePacketData(pkt.Buf.Bytes()); err != nil {
		if !sendError(ctx, errc, err) {
			_ = FreeSerializeBuffer(pkt.Buf)
			return false
		}
	}
	if err := FreeSerializeBuffer(pkt.Buf); err != nil {
		return sendError(ctx, errc, err)
	}
	return true
}

func sendError(ctx context.Context, out chan<- error, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case out <- err:
		return true
	}
}
