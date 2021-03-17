package scan

import (
	"context"
	"encoding/json"
	"fmt"
)

type Result interface {
	fmt.Stringer
	json.Marshaler
	ID() string
}

type ResultChan struct {
	ctx             context.Context
	results         chan Result
	internalResults chan Result
}

func NewResultChan(ctx context.Context, capacity int) *ResultChan {
	results := make(chan Result, capacity)
	internalResults := make(chan Result, capacity)

	copyChans := func() {
		defer close(results)
		for {
			select {
			case <-ctx.Done():
				return
			case v := <-internalResults:
				select {
				case <-ctx.Done():
					return
				case results <- v:
				}
			}
		}
	}
	go copyChans()

	return &ResultChan{
		ctx:             ctx,
		results:         results,
		internalResults: internalResults,
	}
}

func (c *ResultChan) Chan() <-chan Result {
	return c.results
}

func (c *ResultChan) Put(r Result) {
	select {
	case <-c.ctx.Done():
		return
	case c.internalResults <- r:
	}
}
