package packet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type typedDoneSender interface {
	// SendPackets exposes the expected typed completion contract.
	SendPackets(ctx context.Context, in <-chan *BufferData) (done <-chan struct{}, errc <-chan error)
}

var _ typedDoneSender = (Sender)(nil)

func TestSenderWithEmptyChannel(t *testing.T) {
	t.Parallel()
	in := make(chan *BufferData)
	close(in)

	ctrl := gomock.NewController(t)
	w := NewMockWriter(ctrl)
	s := NewSender(w)

	done, errc := s.SendPackets(context.Background(), in)

	result := chanToSlice(t, errc, 0)
	require.Empty(t, result, "error slice is not empty")
	doneResult := chanToSlice(t, done, 0)
	require.Empty(t, doneResult, "done channel is not empty")
}

func TestSenderWithOnePacket(t *testing.T) {
	t.Parallel()
	in := make(chan *BufferData, 1)
	data := []byte{0x1, 0x2, 0x3}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, gopacket.Payload(data))
	require.NoError(t, err)
	in <- &BufferData{Buf: buffer}
	close(in)

	expectedData := make([]byte, len(data))
	copy(expectedData, data)

	ctrl := gomock.NewController(t)
	w := NewMockWriter(ctrl)
	w.EXPECT().WritePacketData(expectedData).Return(nil)
	s := NewSender(w)

	done, errc := s.SendPackets(context.Background(), in)

	result := chanToSlice(t, errc, 0)
	require.Empty(t, result, "error slice is not empty")
	doneResult := chanToSlice(t, done, 0)
	require.Empty(t, doneResult, "done channel is not empty")
}

func TestSenderWithTwoPackets(t *testing.T) {
	t.Parallel()
	in := make(chan *BufferData, 2)

	data := []byte{0x1, 0x2, 0x3}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, gopacket.Payload(data))
	require.NoError(t, err)
	in <- &BufferData{Buf: buffer}

	data2 := []byte{0x2, 0x3, 0x4}
	buffer2 := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer2, gopacket.SerializeOptions{}, gopacket.Payload(data2))
	require.NoError(t, err)
	in <- &BufferData{Buf: buffer2}

	close(in)

	expectedData := make([]byte, len(data))
	copy(expectedData, data)
	expectedData2 := make([]byte, len(data2))
	copy(expectedData2, data2)

	ctrl := gomock.NewController(t)
	w := NewMockWriter(ctrl)
	gomock.InOrder(
		w.EXPECT().WritePacketData(expectedData).Return(nil),
		w.EXPECT().WritePacketData(expectedData2).Return(nil),
	)
	s := NewSender(w)

	done, errc := s.SendPackets(context.Background(), in)

	result := chanToSlice(t, errc, 0)
	require.Empty(t, result, "error slice is not empty")
	doneResult := chanToSlice(t, done, 0)
	require.Empty(t, doneResult, "done channel is not empty")
}

func TestSenderWithInvalidPacketReturnsError(t *testing.T) {
	t.Parallel()
	in := make(chan *BufferData, 1)
	in <- &BufferData{Err: errors.New("invalid data")}
	close(in)

	ctrl := gomock.NewController(t)
	w := NewMockWriter(ctrl)
	s := NewSender(w)

	done, errc := s.SendPackets(context.Background(), in)

	result := chanToSlice(t, errc, 1)
	require.Len(t, result, 1, "error slice size is invalid")
	require.Error(t, result[0])

	doneResult := chanToSlice(t, done, 0)
	require.Empty(t, doneResult, "done channel is not empty")
}

func TestSenderWithWriteErrorReturnsError(t *testing.T) {
	t.Parallel()
	in := make(chan *BufferData, 1)

	data := []byte{0x1, 0x2, 0x3}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, gopacket.Payload(data))
	require.NoError(t, err)
	in <- &BufferData{Buf: buffer}
	close(in)

	ctrl := gomock.NewController(t)
	w := NewMockWriter(ctrl)
	w.EXPECT().WritePacketData(data).Return(errors.New("write error"))
	s := NewSender(w)

	done, errc := s.SendPackets(context.Background(), in)

	result := chanToSlice(t, errc, 1)
	require.Len(t, result, 1, "error slice size is invalid")
	require.Error(t, result[0])

	doneResult := chanToSlice(t, done, 0)
	require.Empty(t, doneResult, "done channel is not empty")
}

func TestSenderWithTimeout(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWriter(ctrl)
	s := NewSender(w)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	done, errc := s.SendPackets(ctx, nil)
	select {
	case <-errc:
	case <-time.After(1 * time.Second):
		require.FailNow(t, "exit timeout")
	}
	result := chanToSlice(t, done, 0)
	require.Empty(t, result, "error slice is not empty")
}

func TestSenderCancellationWithFullErrorChannel(t *testing.T) {
	t.Parallel()

	const errorChannelCapacity = 100
	in := make(chan *BufferData, errorChannelCapacity+1)
	for range errorChannelCapacity + 1 {
		in <- &BufferData{Err: errors.New("invalid data")}
	}
	close(in)

	ctrl := gomock.NewController(t)
	w := NewMockWriter(ctrl)
	s := NewSender(w)
	ctx, cancel := context.WithCancel(context.Background())
	done, errc := s.SendPackets(ctx, in)

	require.Eventually(t, func() bool {
		return len(errc) == cap(errc)
	}, time.Second, time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		require.FailNow(t, "sender did not stop after context cancellation")
	}
}
