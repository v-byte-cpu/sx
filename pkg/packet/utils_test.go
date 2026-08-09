package packet

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const waitTimeout = 3 * time.Second

func chanToSlice[T any](t *testing.T, in <-chan T, expectedLen int) []T {
	t.Helper()
	result := []T{}
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
			require.FailNow(t, "read timeout")
		}
	}
	return result
}
