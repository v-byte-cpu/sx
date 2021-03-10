package packet

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
)

func newCaptureInfo() *gopacket.CaptureInfo {
	return &gopacket.CaptureInfo{}
}

func TestReceivePacketsWithUnrecoverableError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		exitError error
	}{
		{
			name:      "io.EOF",
			exitError: io.EOF,
		},
		{
			name:      "io.ErrUnexpectedEOF",
			exitError: io.ErrUnexpectedEOF,
		},
		{
			name:      "io.ErrNoProgress",
			exitError: io.ErrNoProgress,
		},
		{
			name:      "io.ErrClosedPipe",
			exitError: io.ErrClosedPipe,
		},
		{
			name:      "io.ErrShortBuffer",
			exitError: io.ErrShortBuffer,
		},
		{
			name:      "syscall.EBADF",
			exitError: syscall.EBADF,
		},
		{
			name:      "poll.ErrFileClosing",
			exitError: errors.New("use of closed file"),
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			sr := NewMockReader(ctrl)
			sr.EXPECT().ReadPacketData().Return(nil, nil, io.EOF)
			p := NewMockProcessor(ctrl)
			r := NewReceiver(sr, p)

			out := r.ReceivePackets(context.Background())
			result := chanToSlice(t, chanErrToGeneric(out), 0)
			assert.Equal(t, 0, len(result), "error slice is not empty")
		})
	}
}

func TestReceivePacketsOnePacket(t *testing.T) {
	t.Parallel()

	data := []byte{0x1, 0x2, 0x3}
	expectedData := make([]byte, len(data))
	copy(expectedData, data)

	ctrl := gomock.NewController(t)
	sr := NewMockReader(ctrl)
	gomock.InOrder(
		sr.EXPECT().ReadPacketData().Return(data, newCaptureInfo(), nil),
		sr.EXPECT().ReadPacketData().Return(nil, nil, io.EOF),
	)

	p := NewMockProcessor(ctrl)
	p.EXPECT().
		ProcessPacketData(expectedData, newCaptureInfo()).Return(nil)
	r := NewReceiver(sr, p)

	out := r.ReceivePackets(context.Background())
	result := chanToSlice(t, chanErrToGeneric(out), 0)
	assert.Equal(t, 0, len(result), "error slice is not empty")
}

func TestReceivePacketsOnePacketWithProcessError(t *testing.T) {
	t.Parallel()

	data := []byte{0x1, 0x2, 0x3}

	ctrl := gomock.NewController(t)
	sr := NewMockReader(ctrl)
	gomock.InOrder(
		sr.EXPECT().ReadPacketData().Return(data, newCaptureInfo(), nil),
		sr.EXPECT().ReadPacketData().Return(nil, nil, io.EOF),
	)

	p := NewMockProcessor(ctrl)
	notNil := gomock.Not(gomock.Nil())
	p.EXPECT().
		ProcessPacketData(notNil, notNil).Return(errors.New("process error"))
	r := NewReceiver(sr, p)

	out := r.ReceivePackets(context.Background())
	result := chanToSlice(t, chanErrToGeneric(out), 1)
	assert.Equal(t, 1, len(result), "error slice is invalid")
	assert.Error(t, result[0].(error))
}

func TestReceivePacketsOnePacketWithRetryError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		exitError error
	}{
		{
			name:      "syscall.EAGAIN",
			exitError: syscall.EAGAIN,
		},
		{
			name:      "temporaryNetError",
			exitError: &net.OpError{Op: "accept", Err: syscall.ECONNRESET},
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := []byte{0x1, 0x2, 0x3}
			expectedData := make([]byte, len(data))
			copy(expectedData, data)

			ctrl := gomock.NewController(t)
			sr := NewMockReader(ctrl)
			gomock.InOrder(
				sr.EXPECT().ReadPacketData().Return(nil, nil, tt.exitError),
				sr.EXPECT().ReadPacketData().Return(data, newCaptureInfo(), nil),
				sr.EXPECT().ReadPacketData().Return(nil, nil, io.EOF),
			)

			p := NewMockProcessor(ctrl)
			p.EXPECT().
				ProcessPacketData(expectedData, newCaptureInfo()).Return(nil)
			r := NewReceiver(sr, p)

			out := r.ReceivePackets(context.Background())
			result := chanToSlice(t, chanErrToGeneric(out), 0)
			assert.Equal(t, 0, len(result), "error slice is not empty")
		})
	}
}

func TestReceivePacketsOnePacketWithUnknownError(t *testing.T) {
	t.Parallel()

	data := []byte{0x1, 0x2, 0x3}
	expectedData := make([]byte, len(data))
	copy(expectedData, data)

	ctrl := gomock.NewController(t)
	sr := NewMockReader(ctrl)
	gomock.InOrder(
		sr.EXPECT().ReadPacketData().Return(nil, nil, errors.New("unknown error")),
		sr.EXPECT().ReadPacketData().Return(data, newCaptureInfo(), nil),
		sr.EXPECT().ReadPacketData().Return(nil, nil, io.EOF),
	)

	p := NewMockProcessor(ctrl)
	p.EXPECT().
		ProcessPacketData(expectedData, newCaptureInfo()).Return(nil)
	r := NewReceiver(sr, p)

	out := r.ReceivePackets(context.Background())
	result := chanToSlice(t, chanErrToGeneric(out), 1)
	assert.Equal(t, 1, len(result), "error slice length is invalid")
	assert.Error(t, result[0].(error))
}

func TestReceivePacketsOnePacketWithContextCancel(t *testing.T) {
	t.Parallel()

	data := []byte{0x1, 0x2, 0x3}
	expectedData := make([]byte, len(data))
	copy(expectedData, data)

	ctrl := gomock.NewController(t)
	sr := NewMockReader(ctrl)
	sr.EXPECT().ReadPacketData().Return(data, newCaptureInfo(), nil)

	p := NewMockProcessor(ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	p.EXPECT().
		ProcessPacketData(expectedData, newCaptureInfo()).Return(nil).
		Do(func(data []byte, ci *gopacket.CaptureInfo) error {
			cancel()
			return nil
		})
	r := NewReceiver(sr, p)

	out := r.ReceivePackets(ctx)
	result := chanToSlice(t, chanErrToGeneric(out), 0)
	assert.Equal(t, 0, len(result), "error slice is not empty")
}
