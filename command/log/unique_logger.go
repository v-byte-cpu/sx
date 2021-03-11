package log

import (
	"context"

	"github.com/v-byte-cpu/sx/pkg/scan/arp"
)

type UniqueLogger struct {
	ctx    context.Context
	logger Logger
}

func NewUniqueLogger(ctx context.Context, logger Logger) *UniqueLogger {
	return &UniqueLogger{ctx, logger}
}

func (l *UniqueLogger) Error(err error) {
	l.logger.Error(err)
}

func (l *UniqueLogger) LogResults(results <-chan *arp.ScanResult) {
	l.logger.LogResults(l.uniqResults(results))
}

func (l *UniqueLogger) uniqResults(in <-chan *arp.ScanResult) <-chan *arp.ScanResult {
	results := make(chan *arp.ScanResult, cap(in))
	go func() {
		defer close(results)
		var member struct{}
		set := make(map[string]interface{})

		for result := range in {
			id := result.ID()
			if _, exists := set[id]; !exists {
				set[id] = member
				select {
				case results <- result:
				case <-l.ctx.Done():
					return
				}
			}
		}
	}()
	return results
}
