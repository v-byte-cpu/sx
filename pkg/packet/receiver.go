//go:generate mockgen -destination=mock_receiver_test.go -package=packet -source receiver.go

package packet

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
)

type Processor interface {
	ProcessPacketData(data []byte, ci *gopacket.CaptureInfo) error
}

type Reader interface {
	ReadPacketData() (data []byte, ci *gopacket.CaptureInfo, err error)
}

type Receiver interface {
	ReceivePackets(ctx context.Context) <-chan error
}

func NewReceiver(sr Reader, p Processor) Receiver {
	return &receiver{sr, p}
}

type receiver struct {
	sr Reader
	p  Processor
}

func isTemporaryError(err error) bool {
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	nerr, ok := err.(net.Error)
	return ok && nerr.Timeout()
}

func isUnrecoverableError(err error) bool {
	switch err {
	case io.EOF, io.ErrUnexpectedEOF, io.ErrNoProgress,
		io.ErrClosedPipe, io.ErrShortBuffer, syscall.EBADF:
		return true
	default:
		return strings.Contains(err.Error(), "use of closed file")
	}
}

func (r *receiver) ReceivePackets(ctx context.Context) <-chan error {
	errc := make(chan error, 100)
	go func() {
		defer close(errc)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			data, ci, err := r.sr.ReadPacketData()
			if err != nil {
				// Immediately retry for temporary errors
				if isTemporaryError(err) {
					continue
				}
				if isUnrecoverableError(err) {
					return
				}
				// Log unknown error
				select {
				case <-ctx.Done():
					return
				case errc <- err:
				}
				// Sleep briefly and try again
				time.Sleep(5 * time.Millisecond)
				continue
			}
			if err := r.p.ProcessPacketData(data, ci); err != nil {
				select {
				case <-ctx.Done():
					return
				case errc <- err:
				}
			}
		}
	}()
	return errc
}
