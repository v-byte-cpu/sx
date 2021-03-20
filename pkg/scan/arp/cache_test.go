//go:generate mockgen -package arp -destination=mock_request_test.go github.com/v-byte-cpu/sx/pkg/scan RequestGenerator

package arp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

func TestCachePut(t *testing.T) {
	t.Parallel()
	cache := NewCache()
	cache.Put(net.IPv4(192, 168, 0, 2).To4(), net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6})
	mac := cache.Get(net.IPv4(192, 168, 0, 2).To4())
	require.Equal(t, mac, net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6})
}

func TestCacheDelete(t *testing.T) {
	t.Parallel()
	cache := NewCache()
	cache.Put(net.IPv4(192, 168, 0, 2).To4(), net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6})
	cache.Delete(net.IPv4(192, 168, 0, 2).To4())
	require.Nil(t, cache.Get(net.IPv4(192, 168, 0, 2).To4()))
}

func TestFillCache(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []*ipMacPair
		err      bool
	}{
		{
			name:  "oneIP",
			input: `{"ip":"192.168.0.2","mac":"01:02:03:04:05:06"}`,
			expected: []*ipMacPair{
				{
					ip:  net.IPv4(192, 168, 0, 2).To4(),
					mac: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
				},
			},
		},
		{
			name: "twoIP",
			input: strings.Join([]string{
				`{"ip":"192.168.0.2","mac":"01:02:03:04:05:06"}`,
				`{"ip":"192.168.0.3","mac":"11:12:13:14:15:16"}`,
			}, "\n"),
			expected: []*ipMacPair{
				{
					ip:  net.IPv4(192, 168, 0, 2).To4(),
					mac: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
				},
				{
					ip:  net.IPv4(192, 168, 0, 3).To4(),
					mac: net.HardwareAddr{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
				},
			},
		},
		{
			name:  "invalidJson",
			input: `{"ip":"192`,
			err:   true,
		},
		{
			name:  "invalidIP",
			input: `{"ip":"192.1680","mac":"01:02:03:04:05:06"}`,
			err:   true,
		},
		{
			name:  "invalidMAC",
			input: `{"ip":"192.168.0.2","mac":"01:02:03"}`,
			err:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewCache()
			err := FillCache(cache, strings.NewReader(tt.input))
			if tt.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			for _, pair := range tt.expected {
				mac := cache.Get(pair.ip)
				require.Equal(t, pair.mac, mac)
			}
		})
	}
}

type ipMacPair struct {
	ip  net.IP
	mac net.HardwareAddr
}

func TestCacheRequestGenerator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		gatewayIP        net.IP
		ipMacPairs       []*ipMacPair
		requests         []*scan.Request
		expectedRequests []*scan.Request
	}{
		{
			name: "oneRequest",
			ipMacPairs: []*ipMacPair{
				{
					ip:  net.IPv4(192, 168, 0, 2).To4(),
					mac: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
				},
			},
			requests: []*scan.Request{
				{DstIP: net.IPv4(192, 168, 0, 2).To4()},
			},
			expectedRequests: []*scan.Request{
				{
					DstIP:  net.IPv4(192, 168, 0, 2).To4(),
					DstMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
				},
			},
		},
		{
			name: "twoRequests",
			ipMacPairs: []*ipMacPair{
				{
					ip:  net.IPv4(192, 168, 0, 2).To4(),
					mac: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
				},
				{
					ip:  net.IPv4(192, 168, 0, 3).To4(),
					mac: net.HardwareAddr{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
				},
			},
			requests: []*scan.Request{
				{DstIP: net.IPv4(192, 168, 0, 3).To4()},
				{DstIP: net.IPv4(192, 168, 0, 2).To4()},
			},
			expectedRequests: []*scan.Request{
				{
					DstIP:  net.IPv4(192, 168, 0, 3).To4(),
					DstMAC: net.HardwareAddr{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
				},
				{
					DstIP:  net.IPv4(192, 168, 0, 2).To4(),
					DstMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
				},
			},
		},
		{
			name:      "oneRequestWithGatewayIP",
			gatewayIP: net.IPv4(192, 168, 0, 1).To4(),
			ipMacPairs: []*ipMacPair{
				{
					ip:  net.IPv4(192, 168, 0, 1).To4(),
					mac: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
				},
			},
			requests: []*scan.Request{
				{DstIP: net.IPv4(10, 168, 0, 2).To4()},
			},
			expectedRequests: []*scan.Request{
				{
					DstIP:  net.IPv4(10, 168, 0, 2).To4(),
					DstMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
				},
			},
		},
		{
			name:      "twoRequestsWithGatewayIP",
			gatewayIP: net.IPv4(192, 168, 0, 1).To4(),
			ipMacPairs: []*ipMacPair{
				{
					ip:  net.IPv4(192, 168, 0, 1).To4(),
					mac: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
				},
			},
			requests: []*scan.Request{
				{DstIP: net.IPv4(10, 168, 0, 2).To4()},
				{DstIP: net.IPv4(10, 168, 0, 3).To4()},
			},
			expectedRequests: []*scan.Request{
				{
					DstIP:  net.IPv4(10, 168, 0, 2).To4(),
					DstMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
				},
				{
					DstIP:  net.IPv4(10, 168, 0, 3).To4(),
					DstMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
				},
			},
		},
		{
			name:       "oneRequestWithCacheMiss",
			ipMacPairs: []*ipMacPair{},
			requests: []*scan.Request{
				{DstIP: net.IPv4(10, 168, 0, 2).To4()},
			},
			expectedRequests: []*scan.Request{
				{
					DstIP: net.IPv4(10, 168, 0, 2).To4(),
					Err:   fmt.Errorf("no destination MAC address for %s", net.IPv4(10, 168, 0, 2)),
				},
			},
		},
	}

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			done := make(chan interface{})

			go func() {
				defer close(done)

				// prefill ARP cache
				cache := NewCache()
				for _, ipMac := range tt.ipMacPairs {
					cache.Put(ipMac.ip, ipMac.mac)
				}
				// prefil input requests
				requestsCh := make(chan *scan.Request, len(tt.requests))
				for _, request := range tt.requests {
					requestsCh <- request
				}
				close(requestsCh)

				ctrl := gomock.NewController(t)
				reqgen := NewMockRequestGenerator(ctrl)

				ctx := context.Background()
				scanRange := &scan.Range{}
				reqgen.EXPECT().GenerateRequests(ctx, scanRange).Return(requestsCh, nil)

				cachegen := NewCacheRequestGenerator(reqgen, tt.gatewayIP, cache)
				results, err := cachegen.GenerateRequests(ctx, scanRange)
				require.NoError(t, err)

				for _, expectedResult := range tt.expectedRequests {
					result := <-results
					require.Equal(t, expectedResult, result)
				}

				_, ok := <-results
				require.False(t, ok, "results chan is not empty")

			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("test timeout")
			}
		})
	}
}

func TestCacheRequestGeneratorReturnsError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	reqgen := NewMockRequestGenerator(ctrl)
	reqgen.EXPECT().GenerateRequests(gomock.Any(), gomock.Any()).
		Return(nil, errors.New("request error"))

	cachegen := NewCacheRequestGenerator(reqgen, nil, NewCache())
	_, err := cachegen.GenerateRequests(context.Background(), &scan.Range{})
	require.Error(t, err)
}
