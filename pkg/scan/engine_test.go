//go:generate go tool mockgen -package scan -destination=mock_sendreceiver_test.go github.com/v-byte-cpu/sx/pkg/packet Sender,Receiver

package scan

import (
	"context"
	"errors"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/packet"
	"go.uber.org/mock/gomock"
	"go.uber.org/ratelimit"
)

type typedDoneEngine interface {
	// Start exposes the expected typed completion contract.
	Start(ctx context.Context, r *Range) (done <-chan struct{}, errc <-chan error)
}

var _ typedDoneEngine = (Engine)(nil)
var _ EngineResulter = (*ScanEngine)(nil)

func TestMergeChannelsErrorsEmptyChannels(t *testing.T) {
	t.Parallel()
	c1 := make(chan error)
	close(c1)
	c2 := make(chan error)
	close(c2)

	out := mergeChannels(context.Background(), 100, c1, c2)
	result := chanToSlice(t, out, 0)

	require.Empty(t, result, "error slice is not empty")
}

func TestMergeChannelsErrorsOneElementAndEmptyChannel(t *testing.T) {
	t.Parallel()
	c1 := make(chan error, 1)
	c1 <- errors.New("test error")
	close(c1)
	c2 := make(chan error)
	close(c2)

	out := mergeChannels(context.Background(), 100, c1, c2)
	result := chanToSlice(t, out, 1)

	require.Len(t, result, 1, "error slice size is invalid")
	require.Error(t, result[0])
}

func TestMergeChannelsErrorsTwoElements(t *testing.T) {
	t.Parallel()
	c1 := make(chan error, 1)
	c1 <- errors.New("test error")
	close(c1)
	c2 := make(chan error, 1)
	c2 <- errors.New("test error")
	close(c2)

	out := mergeChannels(context.Background(), 100, c1, c2)
	result := chanToSlice(t, out, 2)

	require.Len(t, result, 2, "error slice size is invalid")
	require.Error(t, result[0])
	require.Error(t, result[1])
}

func TestMergeChannelsErrorsContextExit(t *testing.T) {
	t.Parallel()
	c1 := make(chan error)
	defer close(c1)
	c2 := make(chan error)
	defer close(c2)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	out := mergeChannels(ctx, 100, c1, c2)
	result := chanToSlice(t, out, 0)

	require.Empty(t, result, "error slice is not empty")
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

	result := chanToSlice(t, out, 2)
	require.Len(t, result, 2, "error slice is invalid")
	require.Error(t, result[0])
	require.Error(t, result[1])
}

func TestPacketSourceReturnsError(t *testing.T) {
	t.Parallel()

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

	reqgen.EXPECT().GenerateRequests(gomock.Not(gomock.Nil()), scanRange).
		Return(nil, errors.New("generate error"))

	ps := NewPacketSource(reqgen, pktgen)
	results := chanToSlice(t, ps.Packets(context.Background(), scanRange), 1)
	require.Error(t, results[0].Err)
}

func TestPacketSourceReturnsData(t *testing.T) {
	t.Parallel()

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
	results := chanToSlice(t, ps.Packets(context.Background(), scanRange), 1)
	require.NoError(t, results[0].Err)
	require.Equal(t, data.Buf, results[0].Buf)
}

func TestRateLimitScanner(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	scanner := NewMockScanner(ctrl)

	req1 := &Request{DstIP: net.IPv4(192, 168, 0, 1), DstPort: 22}
	expectedResult := &mockScanResult{"id1"}
	scanner.EXPECT().Scan(gomock.Not(gomock.Nil()), req1).
		Return(expectedResult, nil).AnyTimes()

	rateScanner := NewRateLimitScanner(scanner,
		ratelimit.New(2, ratelimit.Per(20*time.Millisecond)))
	timer := time.After(10 * time.Millisecond)
	count := 0
loop:
	for {
		select {
		case <-timer:
			break loop
		default:
			result, err := rateScanner.Scan(context.Background(), req1)
			require.NoError(t, err)
			require.Equal(t, expectedResult, result)
			count++
		}
	}
	require.LessOrEqual(t, count, 2)
}

func TestScanEngineWithRequestGeneratorError(t *testing.T) {
	t.Parallel()

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
}

func TestScanEngineWithRequestError(t *testing.T) {
	t.Parallel()

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
}

func TestScanEngineWithScannerError(t *testing.T) {
	t.Parallel()

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
}

func TestScanEngineWithResults(t *testing.T) {
	t.Parallel()

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
	require.Empty(t, errc, "error channel is not empty")
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
