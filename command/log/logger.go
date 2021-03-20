package log

import (
	"bufio"
	"context"
	"io"
	"time"

	"github.com/v-byte-cpu/sx/pkg/scan"
	"go.uber.org/zap"
)

type Logger interface {
	Error(err error)
	LogResults(ctx context.Context, results <-chan scan.Result)
}

type FlushWriter interface {
	io.Writer
	Flush() error
}

type ResultWriter interface {
	Write(w io.Writer, result scan.Result) error
}

type logger struct {
	zapl  *zap.Logger
	label string

	w             io.Writer
	rw            ResultWriter
	flushInterval time.Duration
}

type LoggerOption func(*logger)

func JSON() LoggerOption {
	return func(l *logger) {
		l.rw = &JSONResultWriter{}
	}
}

func Plain() LoggerOption {
	return func(l *logger) {
		l.rw = &PlainResultWriter{}
	}
}

func FlushInterval(interval time.Duration) LoggerOption {
	return func(l *logger) {
		l.flushInterval = interval
	}
}

func NewLogger(w io.Writer, label string, opts ...LoggerOption) (Logger, error) {
	zapl, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}

	l := &logger{
		zapl:          zapl,
		label:         label,
		rw:            &PlainResultWriter{},
		w:             w,
		flushInterval: 1 * time.Second,
	}
	for _, o := range opts {
		o(l)
	}
	return l, nil
}

func (l *logger) Error(err error) {
	l.zapl.Error(l.label, zap.Error(err))
}

func (l *logger) LogResults(ctx context.Context, results <-chan scan.Result) {
	bw := bufio.NewWriter(l.w)
	defer bw.Flush()
	var err error
	timec := time.After(l.flushInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-results:
			if !ok {
				return
			}
			if err := l.rw.Write(l.w, result); err != nil {
				l.Error(err)
			}
		case <-timec:
			if err = bw.Flush(); err != nil {
				l.Error(err)
			}
			timec = time.After(l.flushInterval)
		}
	}
}
