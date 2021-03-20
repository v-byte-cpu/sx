//go:generate mockgen -package scan -destination=mock_sendreceiver_test.go github.com/v-byte-cpu/sx/pkg/packet Sender,Receiver

package scan

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/jinzhu/copier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/packet"
)

func TestMergeErrChanEmptyChannels(t *testing.T) {
	t.Parallel()
	c1 := make(chan error)
	close(c1)
	c2 := make(chan error)
	close(c2)

	out := mergeErrChan(context.Background(), c1, c2)
	result := chanToSlice(t, chanErrToGeneric(out), 0)

	assert.Equal(t, 0, len(result), "error slice is not empty")
}

func TestMergeErrChanOneElementAndEmptyChannel(t *testing.T) {
	t.Parallel()
	c1 := make(chan error, 1)
	c1 <- errors.New("test error")
	close(c1)
	c2 := make(chan error)
	close(c2)

	out := mergeErrChan(context.Background(), c1, c2)
	result := chanToSlice(t, chanErrToGeneric(out), 1)

	assert.Equal(t, 1, len(result), "error slice size is invalid")
	assert.Error(t, result[0].(error))
}

func TestMergeErrChanTwoElements(t *testing.T) {
	t.Parallel()
	c1 := make(chan error, 1)
	c1 <- errors.New("test error")
	close(c1)
	c2 := make(chan error, 1)
	c2 <- errors.New("test error")
	close(c2)

	out := mergeErrChan(context.Background(), c1, c2)
	result := chanToSlice(t, chanErrToGeneric(out), 2)

	assert.Equal(t, 2, len(result), "error slice size is invalid")
	assert.Error(t, result[0].(error))
	assert.Error(t, result[1].(error))
}

func TestMergeErrChanContextExit(t *testing.T) {
	t.Parallel()
	c1 := make(chan error)
	defer close(c1)
	c2 := make(chan error)
	defer close(c2)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	out := mergeErrChan(ctx, c1, c2)
	result := chanToSlice(t, chanErrToGeneric(out), 0)

	assert.Equal(t, 0, len(result), "error slice is not empty")
}

func TestEngineStartCollectsAllErrors(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	ps := NewMockPacketSource(ctrl)
	notNil := gomock.Not(gomock.Nil())
	packets := make(chan *packet.BufferData)
	close(packets)
	ps.EXPECT().Packets(notNil, notNil).Return(packets).AnyTimes()

	errc1 := make(chan error, 1)
	errc1 <- errors.New("send error")
	close(errc1)
	s := NewMockSender(ctrl)
	s.EXPECT().SendPackets(notNil, notNil).Return(nil, errc1)

	errc2 := make(chan error, 1)
	errc2 <- errors.New("receive error")
	close(errc2)
	r := NewMockReceiver(ctrl)
	r.EXPECT().ReceivePackets(notNil).Return(errc2)
	e := NewEngine(ps, s, r)

	_, out := e.Start(context.Background(), &Range{
		DstSubnet: &net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		},
		StartPort: 888,
		EndPort:   888,
	})

	result := chanToSlice(t, chanErrToGeneric(out), 2)
	assert.Equal(t, 2, len(result), "error slice is invalid")
	assert.Error(t, result[0].(error))
	assert.Error(t, result[1].(error))
}

func TestPacketSourceReturnsError(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})

	go func() {
		defer close(done)

		ctrl := gomock.NewController(t)
		reqgen := NewMockRequestGenerator(ctrl)
		pktgen := NewMockPacketGenerator(ctrl)

		expectedScanRange := &Range{
			SrcIP:     net.IPv4(192, 168, 0, 1),
			SrcMAC:    net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
			StartPort: 22,
			EndPort:   22,
		}
		var scanRange Range
		err := copier.Copy(&scanRange, expectedScanRange)
		require.NoError(t, err)

		reqgen.EXPECT().GenerateRequests(gomock.Not(gomock.Nil()), expectedScanRange).
			Return(nil, errors.New("generate error"))

		ps := NewPacketSource(reqgen, pktgen)
		out := ps.Packets(context.Background(), &scanRange)
		result := <-out
		require.Error(t, result.Err)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}
}

func TestPacketSourceReturnsData(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})

	go func() {
		defer close(done)

		ctrl := gomock.NewController(t)
		reqgen := NewMockRequestGenerator(ctrl)
		pktgen := NewMockPacketGenerator(ctrl)

		scanRange := &Range{
			SrcIP:     net.IPv4(192, 168, 0, 1),
			SrcMAC:    net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
			StartPort: 22,
			EndPort:   22,
		}
		requests := make(chan *Request)
		close(requests)
		reqgen.EXPECT().GenerateRequests(gomock.Not(gomock.Nil()), scanRange).
			Return(requests, nil)

		data := &packet.BufferData{Buf: gopacket.NewSerializeBuffer()}
		dataCh := make(chan *packet.BufferData, 1)
		dataCh <- data
		close(dataCh)
		pktgen.EXPECT().Packets(gomock.Not(gomock.Nil()), requests).Return(dataCh)

		ps := NewPacketSource(reqgen, pktgen)
		out := ps.Packets(context.Background(), scanRange)
		result := <-out
		require.NoError(t, result.Err)
		require.Equal(t, data.Buf, result.Buf)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}
}
