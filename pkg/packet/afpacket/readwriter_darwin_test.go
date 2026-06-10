package afpacket

import (
	"errors"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type packetReadResult struct {
	data []byte
	ci   gopacket.CaptureInfo
	err  error
}

type fakePacketHandle struct {
	linkType layers.LinkType
	filter   string
	reads    []packetReadResult
	writes   [][]byte
	closed   bool
}

func (h *fakePacketHandle) Close() {
	h.closed = true
}

func (h *fakePacketHandle) LinkType() layers.LinkType {
	return h.linkType
}

func (h *fakePacketHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if len(h.reads) == 0 {
		return nil, gopacket.CaptureInfo{}, errors.New("unexpected read")
	}
	result := h.reads[0]
	h.reads = h.reads[1:]
	return result.data, result.ci, result.err
}

func (h *fakePacketHandle) SetBPFFilter(filter string) error {
	h.filter = filter
	return nil
}

func (h *fakePacketHandle) WritePacketData(data []byte) error {
	copied := make([]byte, len(data))
	copy(copied, data)
	h.writes = append(h.writes, copied)
	return nil
}

func TestDarwinNewSourceRejectsUnsupportedLinkType(t *testing.T) {
	t.Parallel()
	handle := &fakePacketHandle{linkType: layers.LinkTypePPP}

	_, err := newSource(handle, false)

	require.ErrorIs(t, err, ErrUnsupportedLinkType)
	require.True(t, handle.closed)
}

func TestDarwinSourceSetBPFFilter(t *testing.T) {
	t.Parallel()
	handle := &fakePacketHandle{linkType: layers.LinkTypeEthernet}
	source, err := newSource(handle, false)
	require.NoError(t, err)

	err = source.SetBPFFilter("tcp", 1518)

	require.NoError(t, err)
	require.Equal(t, "tcp", handle.filter)
}

func TestDarwinSourceReadPacketData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		linkType layers.LinkType
		vpnMode  bool
		input    []byte
		expected []byte
	}{
		{
			name:     "Ethernet",
			linkType: layers.LinkTypeEthernet,
			input:    []byte{0x01, 0x02},
			expected: []byte{0x01, 0x02},
		},
		{
			name:     "Raw",
			linkType: layers.LinkTypeRaw,
			vpnMode:  true,
			input:    []byte{0x45, 0x00},
			expected: []byte{0x45, 0x00},
		},
		{
			name:     "IPv4",
			linkType: layers.LinkTypeIPv4,
			vpnMode:  true,
			input:    []byte{0x45, 0x00},
			expected: []byte{0x45, 0x00},
		},
		{
			name:     "Null",
			linkType: layers.LinkTypeNull,
			vpnMode:  true,
			input:    []byte{0x02, 0x00, 0x00, 0x00, 0x45, 0x00},
			expected: []byte{0x45, 0x00},
		},
		{
			name:     "Loop",
			linkType: layers.LinkTypeLoop,
			vpnMode:  true,
			input:    []byte{0x00, 0x00, 0x00, 0x02, 0x45, 0x00},
			expected: []byte{0x45, 0x00},
		},
	}
	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handle := &fakePacketHandle{
				linkType: tt.linkType,
				reads: []packetReadResult{{
					data: tt.input,
					ci: gopacket.CaptureInfo{
						CaptureLength: len(tt.input),
						Length:        len(tt.input),
					},
				}},
			}
			source, err := newSource(handle, tt.vpnMode)
			require.NoError(t, err)

			data, ci, err := source.ReadPacketData()

			require.NoError(t, err)
			require.Equal(t, tt.expected, data)
			require.Equal(t, len(tt.expected), ci.CaptureLength)
			require.Equal(t, len(tt.expected), ci.Length)
		})
	}
}

func TestDarwinSourceReadShortLoopbackPacketReturnsError(t *testing.T) {
	t.Parallel()
	handle := &fakePacketHandle{
		linkType: layers.LinkTypeNull,
		reads: []packetReadResult{{
			data: []byte{0x02, 0x00, 0x00},
		}},
	}
	source, err := newSource(handle, true)
	require.NoError(t, err)

	_, _, err = source.ReadPacketData()

	require.ErrorIs(t, err, errShortLoopbackPacket)
}

func TestDarwinSourceWritePacketData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		linkType layers.LinkType
		vpnMode  bool
		expected []byte
	}{
		{
			name:     "Ethernet",
			linkType: layers.LinkTypeEthernet,
			expected: []byte{0x45, 0x00},
		},
		{
			name:     "Raw",
			linkType: layers.LinkTypeRaw,
			vpnMode:  true,
			expected: []byte{0x45, 0x00},
		},
		{
			name:     "Null",
			linkType: layers.LinkTypeNull,
			vpnMode:  true,
			expected: []byte{0x02, 0x00, 0x00, 0x00, 0x45, 0x00},
		},
		{
			name:     "Loop",
			linkType: layers.LinkTypeLoop,
			vpnMode:  true,
			expected: []byte{0x00, 0x00, 0x00, 0x02, 0x45, 0x00},
		},
	}
	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handle := &fakePacketHandle{linkType: tt.linkType}
			source, err := newSource(handle, tt.vpnMode)
			require.NoError(t, err)

			err = source.WritePacketData([]byte{0x45, 0x00})

			require.NoError(t, err)
			require.Equal(t, [][]byte{tt.expected}, handle.writes)
		})
	}
}
