//go:generate mockgen -package scan -destination=mock_generator_test.go -source generator.go

package scan

import (
	"context"
	"sync"

	"github.com/google/gopacket"
	"github.com/v-byte-cpu/sx/pkg/packet"
)

type PacketFiller interface {
	Fill(packet gopacket.SerializeBuffer, pair *Request) error
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
	out := make(chan *packet.BufferData)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case pair, ok := <-in:
				if !ok {
					return
				}
				if pair.Err != nil {
					writeBufToChan(ctx, out, &packet.BufferData{Err: pair.Err})
					continue
				}
				// TODO buffer pool
				buf := gopacket.NewSerializeBuffer()
				if err := g.filler.Fill(buf, pair); err != nil {
					writeBufToChan(ctx, out, &packet.BufferData{Err: err})
					continue
				}
				writeBufToChan(ctx, out, &packet.BufferData{Buf: buf})
			}
		}
	}()
	return out
}

func writeBufToChan(ctx context.Context, out chan *packet.BufferData, buf *packet.BufferData) {
	select {
	case <-ctx.Done():
		return
	case out <- buf:
	}
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
	return MergeBufferDataChan(ctx, workers...)
}

// generics would be helpful :)
func MergeBufferDataChan(ctx context.Context, channels ...<-chan *packet.BufferData) <-chan *packet.BufferData {
	var wg sync.WaitGroup
	wg.Add(len(channels))

	out := make(chan *packet.BufferData)
	multiplex := func(c <-chan *packet.BufferData) {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-c:
				if !ok {
					return
				}
				select {
				case <-ctx.Done():
					return
				case out <- e:
				}
			}
		}
	}
	for _, c := range channels {
		go multiplex(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
