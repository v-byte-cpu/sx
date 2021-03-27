package packet

import "time"

type ReadWriter interface {
	Reader
	Writer
}

type Limiter interface {
	// Take should block to make sure that the RPS is met.
	Take() time.Time
}

type rateLimitReadWriter struct {
	ReadWriter
	limiter Limiter
}

func NewRateLimitReadWriter(delegate ReadWriter, limiter Limiter) ReadWriter {
	return &rateLimitReadWriter{ReadWriter: delegate, limiter: limiter}
}

func (rw *rateLimitReadWriter) WritePacketData(pkt []byte) error {
	rw.limiter.Take()
	return rw.ReadWriter.WritePacketData(pkt)
}
