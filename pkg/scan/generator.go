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

type PacketGenerator struct {
	filler PacketFiller
}

func NewPacketGenerator(filler PacketFiller) *PacketGenerator {
	return &PacketGenerator{filler}
}

func (g *PacketGenerator) Packets(ctx context.Context, in <-chan *Request) <-chan *packet.BufferData {
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
				// TODO buffer pool
				buf := gopacket.NewSerializeBuffer()
				if err := g.filler.Fill(buf, pair); err != nil {
					out <- &packet.BufferData{Err: err}
					continue
				}
				out <- &packet.BufferData{Buf: buf}
			}
		}
	}()
	return out
}

type PacketMultiGenerator struct {
	gen        *PacketGenerator
	numWorkers int
}

func NewPacketMultiGenerator(filler PacketFiller, numWorkers int) *PacketMultiGenerator {
	gen := &PacketGenerator{filler}
	return &PacketMultiGenerator{gen, numWorkers}
}

func (g *PacketMultiGenerator) Packets(ctx context.Context, in <-chan *Request) <-chan *packet.BufferData {
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
