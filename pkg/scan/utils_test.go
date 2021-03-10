package scan

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const waitTimeout = 3 * time.Second

func chanToSlice(t *testing.T, in <-chan interface{}, expectedLen int) []interface{} {
	t.Helper()
	result := []interface{}{}
loop:
	for {
		select {
		case data, ok := <-in:
			if !ok {
				break loop
			}
			if len(result) == expectedLen {
				require.FailNow(t, "chan size is greater than expected, data:", data)
			}
			result = append(result, data)
		case <-time.After(waitTimeout):
			t.Fatal("read timeout")
		}
	}
	return result
}

func chanErrToGeneric(in <-chan error) <-chan interface{} {
	out := make(chan interface{}, cap(in))
	go func() {
		defer close(out)
		for i := range in {
			out <- i
		}
	}()
	return out
}
