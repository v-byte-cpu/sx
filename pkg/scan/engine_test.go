//go:generate mockgen -package scan -destination=mock_sendreceiver_test.go github.com/v-byte-cpu/sx/pkg/packet Sender,Receiver

package scan

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/packet"
)

func chanErrorToSlice(t *testing.T, in <-chan error, expectedLen int, timeout time.Duration) []error {
	t.Helper()
	result := []error{}
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

// generics would be helpful :)
func chanRequestToSlice(t *testing.T, in <-chan *Request, expectedLen int, timeout time.Duration) []*Request {
	t.Helper()
	result := []*Request{}
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

func TestMergeErrChanEmptyChannels(t *testing.T) {
	t.Parallel()
	c1 := make(chan error)
	close(c1)
	c2 := make(chan error)
	close(c2)
	out := mergeErrChan(context.Background(), c1, c2)

	result := chanErrorToSlice(t, out, 0, 3*time.Second)
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

	result := chanErrorToSlice(t, out, 1, 3*time.Second)
	assert.Equal(t, 1, len(result), "error slice size is invalid")
	assert.Error(t, result[0])
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

	result := chanErrorToSlice(t, out, 2, 3*time.Second)
	assert.Equal(t, 2, len(result), "error slice size is invalid")
	assert.Error(t, result[0])
	assert.Error(t, result[1])
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

	result := chanErrorToSlice(t, out, 0, 3*time.Second)
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
		Subnet: &net.IPNet{
			IP:   net.IPv4(192, 168, 0, 1),
			Mask: net.CIDRMask(32, 32),
		},
		StartPort: 888,
		EndPort:   888,
	})

	result := chanErrorToSlice(t, out, 2, 3*time.Second)
	assert.Equal(t, 2, len(result), "error slice is invalid")
	assert.Error(t, result[0])
	assert.Error(t, result[1])
}
