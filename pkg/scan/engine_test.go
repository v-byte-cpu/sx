//go:generate mockgen -package scan -destination=mock_sendreceiver_test.go github.com/v-byte-cpu/sx/pkg/packet Sender,Receiver

package scan

import (
	"context"
	"errors"
	"net"
	"sort"
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

func TestPacketEngineStartCollectsAllErrors(t *testing.T) {
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
	e := NewPacketEngine(ps, s, r)

	_, out := e.Start(context.Background(), &Range{
		DstSubnet: &net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		},
		Ports: []*PortRange{
			{
				StartPort: 888,
				EndPort:   888,
			},
		},
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
			SrcIP:  net.IPv4(192, 168, 0, 1),
			SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
			Ports: []*PortRange{
				{
					StartPort: 22,
					EndPort:   22,
				},
			},
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
	waitDone(t, done)
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
			SrcIP:  net.IPv4(192, 168, 0, 1),
			SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
			Ports: []*PortRange{
				{
					StartPort: 22,
					EndPort:   22,
				},
			},
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
	waitDone(t, done)
}

func TestScanEngineWithRequestGeneratorError(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})
	go func() {
		defer close(done)

		ctrl := gomock.NewController(t)
		reqgen := NewMockRequestGenerator(ctrl)
		scanner := NewMockScanner(ctrl)
		ctx := context.Background()

		reqgen.EXPECT().GenerateRequests(gomock.Not(gomock.Nil()), &Range{}).
			Return(nil, errors.New("generate error"))
		engine := NewScanEngine(reqgen, scanner, NewResultChan(ctx, 10))

		_, errc := engine.Start(ctx, &Range{})
		err := <-errc
		require.Error(t, err)
	}()
	waitDone(t, done)
}

func TestScanEngineWithRequestError(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})
	go func() {
		defer close(done)

		ctrl := gomock.NewController(t)
		reqgen := NewMockRequestGenerator(ctrl)
		scanner := NewMockScanner(ctrl)
		ctx := context.Background()

		requests := make(chan *Request, 1)
		requests <- &Request{Err: errors.New("request error")}
		close(requests)
		reqgen.EXPECT().GenerateRequests(gomock.Not(gomock.Nil()), &Range{}).
			Return(requests, nil)
		engine := NewScanEngine(reqgen, scanner, NewResultChan(ctx, 10))

		_, errc := engine.Start(ctx, &Range{})
		err := <-errc
		require.Error(t, err)
	}()
	waitDone(t, done)
}

func TestScanEngineWithScannerError(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})
	go func() {
		defer close(done)

		ctrl := gomock.NewController(t)
		reqgen := NewMockRequestGenerator(ctrl)
		scanner := NewMockScanner(ctrl)
		ctx := context.Background()

		requests := make(chan *Request, 1)
		req1 := &Request{DstIP: net.IPv4(192, 168, 0, 1), DstPort: 22}
		requests <- req1
		close(requests)
		reqgen.EXPECT().GenerateRequests(gomock.Not(gomock.Nil()), &Range{}).
			Return(requests, nil)
		scanner.EXPECT().Scan(gomock.Not(gomock.Nil()), req1).Return(nil, errors.New("scan error"))
		engine := NewScanEngine(reqgen, scanner, NewResultChan(ctx, 10))

		_, errc := engine.Start(ctx, &Range{})
		err := <-errc
		require.Error(t, err)
	}()
	waitDone(t, done)
}

func TestScanEngineWithResults(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})
	go func() {
		defer close(done)

		ctrl := gomock.NewController(t)
		reqgen := NewMockRequestGenerator(ctrl)
		scanner := NewMockScanner(ctrl)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		requests := make(chan *Request, 2)
		req1 := &Request{DstIP: net.IPv4(192, 168, 0, 1), DstPort: 22}
		req2 := &Request{DstIP: net.IPv4(192, 168, 0, 2), DstPort: 22}
		requests <- req1
		requests <- req2
		close(requests)
		reqgen.EXPECT().GenerateRequests(gomock.Not(gomock.Nil()), &Range{}).
			Return(requests, nil)

		scanner.EXPECT().Scan(gomock.Not(gomock.Nil()), req1).
			Return(&mockScanResult{"id1"}, nil)
		scanner.EXPECT().Scan(gomock.Not(gomock.Nil()), req2).
			Return(&mockScanResult{"id2"}, nil)

		resultCh := NewResultChan(ctx, 10)
		engine := NewScanEngine(reqgen, scanner, resultCh, WithScanWorkerCount(10))

		done, errc := engine.Start(ctx, &Range{})
		<-done
		results := make([]Result, 2)
		results[0] = <-resultCh.Chan()
		results[1] = <-resultCh.Chan()
		cancel()
		require.Zero(t, len(errc), "error channel is not empty")
		result, ok := <-resultCh.Chan()
		if ok {
			require.Fail(t, "result channel contains more elements than expected: ", result)
		}

		sort.Slice(results, func(i, j int) bool {
			return results[i].ID() < results[j].ID()
		})
		require.Equal(t, []Result{
			&mockScanResult{"id1"},
			&mockScanResult{"id2"},
		}, results)
	}()
	waitDone(t, done)
}

type mockScanResult struct {
	id string
}

func (r *mockScanResult) ID() string {
	return r.id
}

func (r *mockScanResult) String() string {
	return r.id
}

func (r *mockScanResult) MarshalJSON() ([]byte, error) {
	return []byte(r.id), nil
}
