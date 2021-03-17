package log

import (
	"context"

	"github.com/v-byte-cpu/sx/pkg/scan"
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

func (l *UniqueLogger) LogResults(results <-chan scan.Result) {
	l.logger.LogResults(l.uniqResults(results))
}

func (l *UniqueLogger) uniqResults(in <-chan scan.Result) <-chan scan.Result {
	results := make(chan scan.Result, cap(in))
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
