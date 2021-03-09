package packet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSenderWithEmptyChannel(t *testing.T) {
	t.Parallel()
	in := make(chan *BufferData)
	close(in)

	ctrl := gomock.NewController(t)
	w := NewMockWriter(ctrl)
	s := NewSender(w)

	done, errc := s.SendPackets(context.Background(), in)

	out := chanErrToGeneric(errc)
	result := chanToSlice(t, out, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "error slice is not empty")
	result = chanToSlice(t, done, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "error slice is not empty")
}

func TestSenderWithOnePacket(t *testing.T) {
	t.Parallel()
	in := make(chan *BufferData, 1)
	data := []byte{0x1, 0x2, 0x3}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, gopacket.Payload(data))
	in <- &BufferData{Buf: buffer}
	close(in)

	expectedData := make([]byte, len(data))
	copy(expectedData, data)

	ctrl := gomock.NewController(t)
	w := NewMockWriter(ctrl)
	w.EXPECT().WritePacketData(expectedData).Return(nil)
	s := NewSender(w)

	done, errc := s.SendPackets(context.Background(), in)

	out := chanErrToGeneric(errc)
	result := chanToSlice(t, out, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "error slice is not empty")
	result = chanToSlice(t, done, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "error slice is not empty")
}

func TestSenderWithTwoPackets(t *testing.T) {
	t.Parallel()
	in := make(chan *BufferData, 2)

	data := []byte{0x1, 0x2, 0x3}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, gopacket.Payload(data))
	in <- &BufferData{Buf: buffer}

	data2 := []byte{0x2, 0x3, 0x4}
	buffer2 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer2, gopacket.SerializeOptions{}, gopacket.Payload(data2))
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

	out := chanErrToGeneric(errc)
	result := chanToSlice(t, out, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "error slice is not empty")
	result = chanToSlice(t, done, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "error slice is not empty")
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

	out := chanErrToGeneric(errc)
	result := chanToSlice(t, out, 1, 3*time.Second)
	assert.Equal(t, 1, len(result), "error slice size is invalid")
	assert.Error(t, result[0].(error))

	result = chanToSlice(t, done, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "error slice is not empty")
}

func TestSenderWithWriteErrorReturnsError(t *testing.T) {
	t.Parallel()
	in := make(chan *BufferData, 1)

	data := []byte{0x1, 0x2, 0x3}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, gopacket.Payload(data))
	in <- &BufferData{Buf: buffer}
	close(in)

	ctrl := gomock.NewController(t)
	w := NewMockWriter(ctrl)
	w.EXPECT().WritePacketData(data).Return(errors.New("write error"))
	s := NewSender(w)

	done, errc := s.SendPackets(context.Background(), in)

	out := chanErrToGeneric(errc)
	result := chanToSlice(t, out, 1, 3*time.Second)
	assert.Equal(t, 1, len(result), "error slice size is invalid")
	assert.Error(t, result[0].(error))

	result = chanToSlice(t, done, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "error slice is not empty")
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
	result := chanToSlice(t, done, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "error slice is not empty")
}
