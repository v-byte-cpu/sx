package arp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProcessPacketData(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})

	go func() {
		defer close(done)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sm := NewScanMethod(ctx, nil)

		// generate packet data
		packet := gopacket.NewSerializeBuffer()
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
			DstMAC:       net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
			EthernetType: layers.EthernetTypeARP,
		}

		a := &layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     uint8(6),
			ProtAddressSize:   uint8(4),
			Operation:         layers.ARPRequest,
			SourceHwAddress:   net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
			SourceProtAddress: net.IPv4(192, 168, 0, 3).To4(),
			DstHwAddress:      net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
			DstProtAddress:    net.IPv4(192, 168, 0, 2).To4(),
		}
		var opt gopacket.SerializeOptions
		err := gopacket.SerializeLayers(packet, opt, eth, a)
		require.NoError(t, err)

		err = sm.ProcessPacketData(packet.Bytes(), &gopacket.CaptureInfo{})
		require.NoError(t, err)

		result, ok := <-sm.Results()
		if !ok {
			require.FailNow(t, "results chan is empty")
		}
		arpResult := result.(*ScanResult)
		assert.Equal(t, net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6}.String(), arpResult.MAC)
		assert.Equal(t, net.IPv4(192, 168, 0, 3).To4().String(), arpResult.IP)

		cancel()
		_, ok = <-sm.Results()
		require.False(t, ok, "results chan is not closed")
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}
}
