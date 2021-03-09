package scan

import (
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/packet"
)

func chanBufferDataToGeneric(in <-chan *packet.BufferData) <-chan interface{} {
	out := make(chan interface{}, cap(in))
	go func() {
		defer close(out)
		for i := range in {
			out <- i
		}
	}()
	return out
}

func chanToSlice(t *testing.T, in <-chan interface{}, expectedLen int, timeout time.Duration) []interface{} {
	t.Helper()
	result := []interface{}{}
loop:
	for {
		select {
		case data, ok := <-in:
			if !ok {
				break loop
			}
			if len(result) == expectedLen {
				require.FailNow(t, "chan size is greater than expected, data:", data)
			}
			result = append(result, data)
		case <-time.After(timeout):
			t.Fatal("read timeout")
		}
	}
	return result
}

func TestGeneratorPacketsWithEmptyChannel(t *testing.T) {
	t.Parallel()
	in := make(chan *Request)
	close(in)

	ctrl := gomock.NewController(t)
	f := NewMockPacketFiller(ctrl)
	g := NewPacketGenerator(f)

	out := chanBufferDataToGeneric(g.Packets(context.Background(), in))
	result := chanToSlice(t, out, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "result is not empty")
}

func TestMultiGeneratorPacketsWithEmptyChannel(t *testing.T) {
	t.Parallel()
	in := make(chan *Request)
	close(in)

	ctrl := gomock.NewController(t)
	f := NewMockPacketFiller(ctrl)
	g := NewPacketMultiGenerator(f, runtime.NumCPU())

	out := chanBufferDataToGeneric(g.Packets(context.Background(), in))
	result := chanToSlice(t, out, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "result is not empty")
}

func TestGeneratorPacketsWithOnePair(t *testing.T) {
	t.Parallel()
	port := uint16(888)

	in := make(chan *Request, 1)
	in <- &Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port}
	close(in)

	ctrl := gomock.NewController(t)
	f := NewMockPacketFiller(ctrl)
	f.EXPECT().
		Fill(gomock.Not(gomock.Nil()),
			&Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port})

	g := NewPacketGenerator(f)

	out := chanBufferDataToGeneric(g.Packets(context.Background(), in))
	results := chanToSlice(t, out, 1, 3*time.Second)

	assert.Equal(t, 1, len(results), "result size is invalid")
	result := results[0].(*packet.BufferData)
	assert.NoError(t, result.Err)
	assert.NotNil(t, result.Buf)
}

func TestMultiGeneratorPacketsWithOnePair(t *testing.T) {
	t.Parallel()
	port := uint16(888)

	in := make(chan *Request, 1)
	in <- &Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port}
	close(in)

	ctrl := gomock.NewController(t)
	f := NewMockPacketFiller(ctrl)
	f.EXPECT().
		Fill(gomock.Not(gomock.Nil()),
			&Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port})

	g := NewPacketMultiGenerator(f, runtime.NumCPU())

	out := chanBufferDataToGeneric(g.Packets(context.Background(), in))
	results := chanToSlice(t, out, 1, 3*time.Second)

	assert.Equal(t, 1, len(results), "result size is invalid")
	result := results[0].(*packet.BufferData)
	assert.NoError(t, result.Err)
	assert.NotNil(t, result.Buf)
}

func TestGeneratorPacketsWithTwoPairs(t *testing.T) {
	t.Parallel()
	port := uint16(888)

	in := make(chan *Request, 2)
	in <- &Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port}
	in <- &Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port + 1}
	close(in)

	ctrl := gomock.NewController(t)
	f := NewMockPacketFiller(ctrl)
	f.EXPECT().
		Fill(gomock.Not(gomock.Nil()),
			&Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port})
	f.EXPECT().
		Fill(gomock.Not(gomock.Nil()),
			&Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port + 1})
	g := NewPacketGenerator(f)

	out := chanBufferDataToGeneric(g.Packets(context.Background(), in))
	results := chanToSlice(t, out, 2, 3*time.Second)

	assert.Equal(t, 2, len(results), "result size is invalid")
	result1 := results[0].(*packet.BufferData)
	result2 := results[1].(*packet.BufferData)
	assert.NoError(t, result1.Err)
	assert.NotNil(t, result1.Buf)
	assert.NoError(t, result2.Err)
	assert.NotNil(t, result2.Buf)
}

func TestMultiGeneratorPacketsWithTwoPairs(t *testing.T) {
	t.Parallel()
	port := uint16(888)

	in := make(chan *Request, 2)
	in <- &Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port}
	in <- &Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port + 1}
	close(in)

	ctrl := gomock.NewController(t)
	f := NewMockPacketFiller(ctrl)
	f.EXPECT().
		Fill(gomock.Not(gomock.Nil()),
			&Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port})
	f.EXPECT().
		Fill(gomock.Not(gomock.Nil()),
			&Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port + 1})

	g := NewPacketMultiGenerator(f, runtime.NumCPU())

	out := chanBufferDataToGeneric(g.Packets(context.Background(), in))
	results := chanToSlice(t, out, 2, 3*time.Second)

	assert.Equal(t, 2, len(results), "result size is invalid")
	result1 := results[0].(*packet.BufferData)
	result2 := results[1].(*packet.BufferData)
	assert.NoError(t, result1.Err)
	assert.NotNil(t, result1.Buf)
	assert.NoError(t, result2.Err)
	assert.NotNil(t, result2.Buf)
}

func TestGeneratorPacketsWithOnePairReturnsError(t *testing.T) {
	t.Parallel()
	port := uint16(888)

	in := make(chan *Request, 1)
	in <- &Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port}
	close(in)

	ctrl := gomock.NewController(t)
	f := NewMockPacketFiller(ctrl)
	f.EXPECT().
		Fill(gomock.Not(gomock.Nil()),
			&Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port}).
		Return(errors.New("failed request"))
	g := NewPacketGenerator(f)

	out := chanBufferDataToGeneric(g.Packets(context.Background(), in))
	results := chanToSlice(t, out, 1, 3*time.Second)

	assert.Equal(t, 1, len(results), "result size is invalid")
	result := results[0].(*packet.BufferData)
	assert.Error(t, result.Err)
	assert.Nil(t, result.Buf)
}

func TestMultiGeneratorPacketsWithOnePairReturnsError(t *testing.T) {
	t.Parallel()
	port := uint16(888)

	in := make(chan *Request, 1)
	in <- &Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port}
	close(in)

	ctrl := gomock.NewController(t)
	f := NewMockPacketFiller(ctrl)
	f.EXPECT().
		Fill(gomock.Not(gomock.Nil()),
			&Request{DstIP: net.IPv4(192, 168, 0, 1).To4(), DstPort: port}).
		Return(errors.New("failed request"))

	g := NewPacketMultiGenerator(f, runtime.NumCPU())

	out := chanBufferDataToGeneric(g.Packets(context.Background(), in))
	results := chanToSlice(t, out, 1, 3*time.Second)

	assert.Equal(t, 1, len(results), "result size is invalid")
	result := results[0].(*packet.BufferData)
	assert.Error(t, result.Err)
	assert.Nil(t, result.Buf)
}

func TestGeneratorPacketsWithTimeout(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	f := NewMockPacketFiller(ctrl)
	g := NewPacketGenerator(f)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	out := g.Packets(ctx, nil)
	select {
	case <-out:
	case <-time.After(1 * time.Second):
		require.FailNow(t, "exit timeout")
	}
}

func TestMultiGeneratorPacketsWithTimeout(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	f := NewMockPacketFiller(ctrl)
	g := NewPacketMultiGenerator(f, runtime.NumCPU())

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	out := g.Packets(ctx, nil)
	select {
	case <-out:
	case <-time.After(1 * time.Second):
		require.FailNow(t, "exit timeout")
	}
}

func TestMergeBufferDataChanEmptyChannels(t *testing.T) {
	t.Parallel()
	c1 := make(chan *packet.BufferData)
	close(c1)
	c2 := make(chan *packet.BufferData)
	close(c2)
	out := chanBufferDataToGeneric(MergeBufferDataChan(context.Background(), c1, c2))

	result := chanToSlice(t, out, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "result slice is not empty")
}

func TestMergeBufferDataChanOneElementAndEmptyChannel(t *testing.T) {
	t.Parallel()
	c1 := make(chan *packet.BufferData, 1)
	c1 <- &packet.BufferData{}
	close(c1)
	c2 := make(chan *packet.BufferData)
	close(c2)
	out := chanBufferDataToGeneric(MergeBufferDataChan(context.Background(), c1, c2))

	result := chanToSlice(t, out, 1, 3*time.Second)
	assert.Equal(t, 1, len(result), "result slice size is invalid")
	assert.NotNil(t, result[0])
}

func TestMergeBufferDataChanTwoElements(t *testing.T) {
	t.Parallel()
	c1 := make(chan *packet.BufferData, 1)
	c1 <- &packet.BufferData{}
	close(c1)
	c2 := make(chan *packet.BufferData, 1)
	c2 <- &packet.BufferData{}
	close(c2)
	out := chanBufferDataToGeneric(MergeBufferDataChan(context.Background(), c1, c2))

	result := chanToSlice(t, out, 2, 3*time.Second)
	assert.Equal(t, 2, len(result), "result slice size is invalid")
	assert.NotNil(t, result[0])
	assert.NotNil(t, result[1])
}

func TestMergeBufferDataChanContextExit(t *testing.T) {
	t.Parallel()
	c1 := make(chan *packet.BufferData)
	defer close(c1)
	c2 := make(chan *packet.BufferData)
	defer close(c2)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	out := chanBufferDataToGeneric(MergeBufferDataChan(ctx, c1, c2))

	result := chanToSlice(t, out, 0, 3*time.Second)
	assert.Equal(t, 0, len(result), "result slice is not empty")
}
