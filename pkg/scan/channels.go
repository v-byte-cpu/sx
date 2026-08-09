package scan

import (
	"context"
	"sync"
)

func sendContext[T any](ctx context.Context, out chan<- T, value T) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case out <- value:
		return true
	}
}

func mergeChannels[T any](ctx context.Context, capacity int, channels ...<-chan T) <-chan T {
	out := make(chan T, capacity)
	var wg sync.WaitGroup
	wg.Add(len(channels))

	for _, channel := range channels {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case value, ok := <-channel:
					if !ok || !sendContext(ctx, out, value) {
						return
					}
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
