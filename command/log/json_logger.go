package log

import (
	"bufio"
	"io"

	"github.com/v-byte-cpu/sx/pkg/scan/arp"
	"go.uber.org/zap"
)

type JSONLogger struct {
	logger *zap.Logger
	writer io.Writer
	label  string
}

func NewJSONLogger(w io.Writer, label string) (*JSONLogger, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	return &JSONLogger{logger, w, label}, nil
}

func (l *JSONLogger) Error(err error) {
	l.logger.Error(l.label, zap.Error(err))
}

func (l *JSONLogger) LogResults(results <-chan *arp.ScanResult) {
	bw := bufio.NewWriter(l.writer)
	defer bw.Flush()
	var err error
	var data []byte
	for result := range results {
		if data, err = result.MarshalJSON(); err != nil {
			l.Error(err)
		}
		if _, err = bw.Write(data); err != nil {
			l.Error(err)
		}
		if err = bw.WriteByte('\n'); err != nil {
			l.Error(err)
		}
	}
}
