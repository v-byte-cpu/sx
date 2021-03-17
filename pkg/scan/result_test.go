package scan

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type result struct {
	Data string
}

func (r *result) String() string {
	return r.Data
}

func (r *result) MarshalJSON() ([]byte, error) {
	return json.Marshal(r)
}

func (r *result) ID() string {
	return r.Data
}

func newResult(data string) *result {
	return &result{data}
}

func TestResultChan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		capacity int
		in       []Result
		expected []Result
	}{
		{
			name:     "OneResult",
			capacity: 1,
			in: []Result{
				newResult("data1"),
			},
			expected: []Result{
				newResult("data1"),
			},
		},
		{
			name:     "TwoResults",
			capacity: 2,
			in: []Result{
				newResult("data1"),
				newResult("data2"),
			},
			expected: []Result{
				newResult("data1"),
				newResult("data2"),
			},
		},
	}

	done := make(chan interface{})
	go func() {
		defer close(done)

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				results := NewResultChan(context.Background(), tt.capacity)
				for _, input := range tt.in {
					results.Put(input)
				}

				for _, expected := range tt.expected {
					result, ok := <-results.Chan()
					require.True(t, ok, "results chan is empty")
					assert.Equal(t, expected.ID(), result.ID())
					assert.Equal(t, expected.String(), result.String())
				}
			})
		}
	}()

	select {
	case <-done:
	case <-time.After(waitTimeout):
		t.Fatal("test timeout")
	}
}

func TestResultChanReadAfterCloseContext(t *testing.T) {
	t.Parallel()
	done := make(chan interface{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		results := NewResultChan(ctx, 1)

		cancel()
		_, ok := <-results.Chan()
		require.False(t, ok, "results chan is not closed")
	}()

	select {
	case <-done:
	case <-time.After(waitTimeout):
		t.Fatal("test timeout")
	}
}

func TestResultChanWriteAfterCloseContext(t *testing.T) {
	t.Parallel()
	done := make(chan interface{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		results := NewResultChan(ctx, 1)

		cancel()
		<-results.Chan()
		results.Put(newResult("data"))
		results.Put(newResult("data2"))
		results.Put(newResult("data3"))
	}()

	select {
	case <-done:
	case <-time.After(waitTimeout):
		t.Fatal("test timeout")
	}
}
