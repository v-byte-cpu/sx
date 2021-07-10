package icmp

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

func TestPacketFillerEthernet(t *testing.T) {
	t.Parallel()

	filler := NewPacketFiller(
		WithType(layers.ICMPv4TypeTimestampRequest), WithCode(1))
	packet := gopacket.NewSerializeBuffer()
	err := filler.Fill(packet, &scan.Request{
		SrcIP:  net.IPv4(192, 168, 0, 3).To4(),
		DstIP:  net.IPv4(192, 168, 0, 2).To4(),
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstMAC: net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
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
	require.Equal(t, uint8(64), ip.TTL)
	require.Equal(t, uint8(5), ip.IHL)
	// IP header + ICMP header + payload length
	require.Equal(t, uint16(20+8+48), ip.Length)
	require.Equal(t, layers.IPProtocolICMPv4, ip.Protocol)
	require.Equal(t, layers.IPv4DontFragment, ip.Flags)

	icmpLayer := resultPacket.Layer(layers.LayerTypeICMPv4)
	require.NotNil(t, icmpLayer, "icmp layer is empty")
	icmp := icmpLayer.(*layers.ICMPv4)
	require.Equal(t, uint8(layers.ICMPv4TypeTimestampRequest), icmp.TypeCode.Type())
	require.Equal(t, uint8(1), icmp.TypeCode.Code())
	require.Equal(t, 48, len(icmp.Payload))
}

func TestPacketFillerIPv4(t *testing.T) {
	t.Parallel()

	filler := NewPacketFiller(
		WithType(layers.ICMPv4TypeTimestampRequest), WithCode(1), WithVPNmode(true))
	packet := gopacket.NewSerializeBuffer()
	err := filler.Fill(packet, &scan.Request{
		SrcIP:  net.IPv4(192, 168, 0, 3).To4(),
		DstIP:  net.IPv4(192, 168, 0, 2).To4(),
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstMAC: net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
	})
	require.NoError(t, err)

	resultPacket := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

	ethLayer := resultPacket.Layer(layers.LayerTypeEthernet)
	require.Nil(t, ethLayer, "ethernet layer is not empty")

	ipLayer := resultPacket.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "ip layer is empty")
	ip := ipLayer.(*layers.IPv4)
	require.Equal(t, net.IPv4(192, 168, 0, 3).To4(), ip.SrcIP.To4())
	require.Equal(t, net.IPv4(192, 168, 0, 2).To4(), ip.DstIP.To4())
	require.Equal(t, uint8(64), ip.TTL)
	require.Equal(t, uint8(5), ip.IHL)
	// IP header + ICMP header + payload length
	require.Equal(t, uint16(20+8+48), ip.Length)
	require.Equal(t, layers.IPProtocolICMPv4, ip.Protocol)
	require.Equal(t, layers.IPv4DontFragment, ip.Flags)

	icmpLayer := resultPacket.Layer(layers.LayerTypeICMPv4)
	require.NotNil(t, icmpLayer, "icmp layer is empty")
	icmp := icmpLayer.(*layers.ICMPv4)
	require.Equal(t, uint8(layers.ICMPv4TypeTimestampRequest), icmp.TypeCode.Type())
	require.Equal(t, uint8(1), icmp.TypeCode.Code())
	require.Equal(t, 48, len(icmp.Payload))
}

func TestPacketFillerPayload(t *testing.T) {
	t.Parallel()

	filler := NewPacketFiller(WithPayload([]byte("abc")),
		WithType(layers.ICMPv4TypeTimestampRequest), WithCode(1))
	packet := gopacket.NewSerializeBuffer()
	err := filler.Fill(packet, &scan.Request{
		SrcIP:  net.IPv4(192, 168, 0, 3).To4(),
		DstIP:  net.IPv4(192, 168, 0, 2).To4(),
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstMAC: net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
	})
	require.NoError(t, err)

	resultPacket := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	ipLayer := resultPacket.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "ip layer is empty")
	ip := ipLayer.(*layers.IPv4)
	require.Equal(t, uint8(5), ip.IHL)
	require.Equal(t, uint8(64), ip.TTL)

	icmpLayer := resultPacket.Layer(layers.LayerTypeICMPv4)
	require.NotNil(t, icmpLayer, "icmp layer is empty")
	icmp := icmpLayer.(*layers.ICMPv4)
	require.Equal(t, []byte("abc"), icmp.Payload)
}

func TestPacketFillerTTL(t *testing.T) {
	t.Parallel()

	filler := NewPacketFiller(WithTTL(37),
		WithType(layers.ICMPv4TypeTimestampRequest), WithCode(1))
	packet := gopacket.NewSerializeBuffer()
	err := filler.Fill(packet, &scan.Request{
		SrcIP:  net.IPv4(192, 168, 0, 3).To4(),
		DstIP:  net.IPv4(192, 168, 0, 2).To4(),
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstMAC: net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
	})
	require.NoError(t, err)

	resultPacket := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	ipLayer := resultPacket.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "ip layer is empty")
	ip := ipLayer.(*layers.IPv4)
	require.Equal(t, uint8(5), ip.IHL)
	require.Equal(t, uint8(37), ip.TTL)
}

func TestPacketFillerIPTotalLength(t *testing.T) {
	t.Parallel()

	filler := NewPacketFiller(WithIPTotalLength(57),
		WithType(layers.ICMPv4TypeTimestampRequest), WithCode(1), WithPayload([]byte("abc")))
	packet := gopacket.NewSerializeBuffer()
	err := filler.Fill(packet, &scan.Request{
		SrcIP:  net.IPv4(192, 168, 0, 3).To4(),
		DstIP:  net.IPv4(192, 168, 0, 2).To4(),
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstMAC: net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
	})
	require.NoError(t, err)

	resultPacket := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	ipLayer := resultPacket.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "ip layer is empty")
	ip := ipLayer.(*layers.IPv4)
	require.Equal(t, uint8(5), ip.IHL)
	require.Equal(t, uint16(57), ip.Length)
}

func TestPacketFillerIPProtocol(t *testing.T) {
	t.Parallel()

	filler := NewPacketFiller(WithIPProtocol(37),
		WithType(layers.ICMPv4TypeTimestampRequest), WithCode(1))
	packet := gopacket.NewSerializeBuffer()
	err := filler.Fill(packet, &scan.Request{
		SrcIP:  net.IPv4(192, 168, 0, 3).To4(),
		DstIP:  net.IPv4(192, 168, 0, 2).To4(),
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstMAC: net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
	})
	require.NoError(t, err)

	resultPacket := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	ipLayer := resultPacket.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "ip layer is empty")
	ip := ipLayer.(*layers.IPv4)
	require.Equal(t, layers.IPProtocol(37), ip.Protocol)
}

func TestPacketFillerIPFlags(t *testing.T) {
	t.Parallel()

	filler := NewPacketFiller(WithIPFlags(uint8(layers.IPv4DontFragment|layers.IPv4MoreFragments)),
		WithType(layers.ICMPv4TypeTimestampRequest), WithCode(1))
	packet := gopacket.NewSerializeBuffer()
	err := filler.Fill(packet, &scan.Request{
		SrcIP:  net.IPv4(192, 168, 0, 3).To4(),
		DstIP:  net.IPv4(192, 168, 0, 2).To4(),
		SrcMAC: net.HardwareAddr{0x1, 0x2, 0x3, 0x4, 0x5, 0x6},
		DstMAC: net.HardwareAddr{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
	})
	require.NoError(t, err)

	resultPacket := gopacket.NewPacket(packet.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	ipLayer := resultPacket.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "ip layer is empty")
	ip := ipLayer.(*layers.IPv4)
	require.Equal(t, layers.IPv4DontFragment|layers.IPv4MoreFragments, ip.Flags)
}

func TestProcessPacketDataEthernet(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})

	go func() {
		defer close(done)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		results := scan.NewResultChan(ctx, 1000)
		p := NewPacketProcessor(ScanType, results, false)

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
				layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeHost),
		}

		opt := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		err := gopacket.SerializeLayers(packet, opt, eth, ip, icmp)
		require.NoError(t, err)

		err = p.ProcessPacketData(packet.Bytes(), &gopacket.CaptureInfo{})
		require.NoError(t, err)

		result, ok := <-p.Results()
		if !ok {
			require.FailNow(t, "results chan is empty")
		}
		icmpResult := result.(*ScanResult)
		assert.Equal(t, ScanType, icmpResult.ScanType)
		assert.Equal(t, net.IPv4(192, 168, 0, 2).To4().String(), icmpResult.IP)
		assert.Equal(t, uint8(64), icmpResult.TTL)
		require.NotNil(t, icmpResult.ICMP)
		assert.Equal(t, uint8(layers.ICMPv4TypeDestinationUnreachable), icmpResult.ICMP.Type)
		assert.Equal(t, uint8(layers.ICMPv4CodeHost), icmpResult.ICMP.Code)

		cancel()
		_, ok = <-p.Results()
		require.False(t, ok, "results chan is not closed")
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}
}

func TestProcessPacketDataIPv4(t *testing.T) {
	t.Parallel()

	done := make(chan interface{})

	go func() {
		defer close(done)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		results := scan.NewResultChan(ctx, 1000)
		p := NewPacketProcessor(ScanType, results, true)

		// generate packet data
		packet := gopacket.NewSerializeBuffer()

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
				layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeHost),
		}

		opt := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		err := gopacket.SerializeLayers(packet, opt, ip, icmp)
		require.NoError(t, err)

		err = p.ProcessPacketData(packet.Bytes(), &gopacket.CaptureInfo{})
		require.NoError(t, err)

		result, ok := <-p.Results()
		if !ok {
			require.FailNow(t, "results chan is empty")
		}
		icmpResult := result.(*ScanResult)
		assert.Equal(t, ScanType, icmpResult.ScanType)
		assert.Equal(t, net.IPv4(192, 168, 0, 2).To4().String(), icmpResult.IP)
		assert.Equal(t, uint8(64), icmpResult.TTL)
		require.NotNil(t, icmpResult.ICMP)
		assert.Equal(t, uint8(layers.ICMPv4TypeDestinationUnreachable), icmpResult.ICMP.Type)
		assert.Equal(t, uint8(layers.ICMPv4CodeHost), icmpResult.ICMP.Code)

		cancel()
		_, ok = <-p.Results()
		require.False(t, ok, "results chan is not closed")
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("test timeout")
	}
}
