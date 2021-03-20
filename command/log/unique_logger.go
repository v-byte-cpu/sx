package log

import (
	"context"

	"github.com/v-byte-cpu/sx/pkg/scan"
)

type UniqueLogger struct {
	logger Logger
}

func NewUniqueLogger(logger Logger) *UniqueLogger {
	return &UniqueLogger{logger}
}

func (l *UniqueLogger) Error(err error) {
	l.logger.Error(err)
}

func (l *UniqueLogger) LogResults(ctx context.Context, results <-chan scan.Result) {
	l.logger.LogResults(ctx, l.uniqResults(ctx, results))
}

func (*UniqueLogger) uniqResults(ctx context.Context, in <-chan scan.Result) <-chan scan.Result {
	results := make(chan scan.Result, cap(in))
	go func() {
		defer close(results)
		var member struct{}
		set := make(map[string]interface{})

		for {
			select {
			case <-ctx.Done():
				return
			case result, ok := <-in:
				if !ok {
					return
				}
				id := result.ID()
				if _, exists := set[id]; !exists {
					set[id] = member
					select {
					case <-ctx.Done():
						return
					case results <- result:
					}
				}
			}
		}
	}()
	return results
}
