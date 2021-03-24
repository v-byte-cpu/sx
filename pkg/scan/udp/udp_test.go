package udp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

func TestPacketFiller(t *testing.T) {
	t.Parallel()

	filler := NewPacketFiller()
	packet := gopacket.NewSerializeBuffer()
	err := filler.Fill(packet, &scan.Request{
		SrcIP:   net.IPv4(192, 168, 0, 3).To4(),
		DstIP:   net.IPv4(192, 168, 0, 2).To4(),
		SrcMAC:  net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstMAC:  net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		DstPort: 4567,
	})
	require.NoError(t, err)

	resultPacket := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	ethLayer := resultPacket.Layer(layers.LayerTypeEthernet)
	require.NotNil(t, ethLayer, "ethernet layer is empty")
	eth := ethLayer.(*layers.Ethernet)
	require.Equal(t, net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6}, eth.SrcMAC)
	require.Equal(t, net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15}, eth.DstMAC)

	ipLayer := resultPacket.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "ip layer is empty")
	ip := ipLayer.(*layers.IPv4)
	require.Equal(t, net.IPv4(192, 168, 0, 3).To4(), ip.SrcIP.To4())
	require.Equal(t, net.IPv4(192, 168, 0, 2).To4(), ip.DstIP.To4())

	udpLayer := resultPacket.Layer(layers.LayerTypeUDP)
	require.NotNil(t, udpLayer, "udp layer is empty")
	udp := udpLayer.(*layers.UDP)
	require.GreaterOrEqual(t, udp.SrcPort, uint16(32768))
	require.LessOrEqual(t, udp.SrcPort, uint16(60999))
	require.Equal(t, uint16(4567), uint16(udp.DstPort))
}

func TestProcessPacketData(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})

	go func() {
		defer close(done)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		results := scan.NewResultChan(ctx, 1000)
		sm := NewScanMethod(nil, results)

		// generate packet data
		packet := gopacket.NewSerializeBuffer()
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
			DstMAC:       net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
			EthernetType: layers.EthernetTypeIPv4,
		}

		ip := &layers.IPv4{
			Version:  4,
			Id:       12345,
			Flags:    layers.IPv4DontFragment,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    net.IPv4(192, 168, 0, 2).To4(),
			DstIP:    net.IPv4(192, 168, 0, 3).To4(),
		}

		icmp := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(
				layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodePort),
		}

		opt := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		err := gopacket.SerializeLayers(packet, opt, eth, ip, icmp)
		require.NoError(t, err)

		err = sm.ProcessPacketData(packet.Bytes(), &gopacket.CaptureInfo{})
		require.NoError(t, err)

		result, ok := <-sm.Results()
		if !ok {
			require.FailNow(t, "results chan is empty")
		}
		udpResult := result.(*ScanResult)
		assert.Equal(t, ScanType, udpResult.ScanType)
		assert.Equal(t, net.IPv4(192, 168, 0, 2).To4().String(), udpResult.IP)
		require.NotNil(t, udpResult.ICMP)
		assert.Equal(t, uint8(layers.ICMPv4TypeDestinationUnreachable), udpResult.ICMP.Type)
		assert.Equal(t, uint8(layers.ICMPv4CodePort), udpResult.ICMP.Code)

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
