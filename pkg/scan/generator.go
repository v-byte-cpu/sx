//go:generate go tool mockgen -package scan -destination=mock_generator_test.go -source generator.go

package scan

import (
	"context"

	"github.com/google/gopacket"
	"github.com/v-byte-cpu/sx/pkg/packet"
)

type PacketFiller interface {
	Fill(packet gopacket.SerializeBuffer, r *Request) error
}

type PacketGenerator interface {
	Packets(ctx context.Context, in <-chan *Request) <-chan *packet.BufferData
}

func NewPacketGenerator(filler PacketFiller) PacketGenerator {
	return &packetGenerator{filler}
}

type packetGenerator struct {
	filler PacketFiller
}

func (g *packetGenerator) Packets(ctx context.Context, in <-chan *Request) <-chan *packet.BufferData {
	out := make(chan *packet.BufferData, 100)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case r, ok := <-in:
				if !ok {
					return
				}
				if !g.sendPacket(ctx, out, r) {
					return
				}
			}
		}
	}()
	return out
}

func (g *packetGenerator) sendPacket(ctx context.Context, out chan<- *packet.BufferData, r *Request) bool {
	if r.Err != nil {
		return sendContext(ctx, out, &packet.BufferData{Err: r.Err})
	}
	buf := packet.NewSerializeBuffer()
	if err := g.filler.Fill(buf, r); err != nil {
		return sendContext(ctx, out, &packet.BufferData{Err: err})
	}
	return sendContext(ctx, out, &packet.BufferData{Buf: buf})
}

func NewPacketMultiGenerator(filler PacketFiller, numWorkers int) PacketGenerator {
	gen := &packetGenerator{filler}
	return &packetMultiGenerator{gen, numWorkers}
}

type packetMultiGenerator struct {
	gen        *packetGenerator
	numWorkers int
}

func (g *packetMultiGenerator) Packets(ctx context.Context, in <-chan *Request) <-chan *packet.BufferData {
	workers := make([]<-chan *packet.BufferData, g.numWorkers)
	for i := 0; i < g.numWorkers; i++ {
		workers[i] = g.gen.Packets(ctx, in)
	}
	return mergeChannels(ctx, len(workers)*100, workers...)
}
