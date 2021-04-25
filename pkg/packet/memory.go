package packet

import (
	"sync"

	"github.com/google/gopacket"
)

var bufferPool = &sync.Pool{
	New: func() interface{} {
		return gopacket.NewSerializeBuffer()
	},
}

func NewSerializeBuffer() gopacket.SerializeBuffer {
	buf := bufferPool.Get().(gopacket.SerializeBuffer)
	return buf
}

func FreeSerializeBuffer(buf gopacket.SerializeBuffer) (err error) {
	if err = buf.Clear(); err != nil {
		return
	}
	bufferPool.Put(buf)
	return
}
