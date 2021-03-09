//+build wireinject

package scan

import (
	"github.com/google/wire"
	"github.com/v-byte-cpu/sx/pkg/packet"
)

type Method interface {
	PacketSource
	packet.Processor
}

func SetupEngine(rw packet.ReadWriter, m Method) *Engine {
	wire.Build(NewEngine,
		packet.NewSender,
		packet.NewReceiver,
		wire.Bind(new(PacketSource), new(Method)),
		wire.Bind(new(packet.Processor), new(Method)),
		wire.Bind(new(packet.Reader), new(packet.ReadWriter)),
		wire.Bind(new(packet.Writer), new(packet.ReadWriter)),
	)
	return nil
}
