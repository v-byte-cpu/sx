package log

import (
	"bufio"
	"io"

	"github.com/v-byte-cpu/sx/pkg/scan/arp"
	"go.uber.org/zap"
)

type PlainLogger struct {
	logger *zap.Logger
	writer io.Writer
	label  string
}

func NewPlainLogger(w io.Writer, label string) (*PlainLogger, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	return &PlainLogger{logger, w, label}, nil
}

func (l *PlainLogger) Error(err error) {
	l.logger.Error(l.label, zap.Error(err))
}

func (l *PlainLogger) LogResults(results <-chan *arp.ScanResult) {
	bw := bufio.NewWriter(l.writer)
	defer bw.Flush()
	var err error
	for result := range results {
		if _, err = bw.WriteString(result.String()); err != nil {
			l.Error(err)
		}
		if err = bw.WriteByte('\n'); err != nil {
			l.Error(err)
		}
	}
}
