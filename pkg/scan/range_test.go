package scan

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewRangeIteratorError(t *testing.T) {
	tests := []int64{-1, 0, 1 << 33}
	for _, input := range tests {
		_, err := newRangeIterator(input)
		require.Equal(t, errRangeSize, err, "no error for %d", input)
	}
}

func TestNewRangeIterator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		n    int
	}{
		{
			name: "1",
			n:    1,
		},
		{
			name: "2",
			n:    2,
		},
		{
			name: "3",
			n:    3,
		},
		{
			name: "4",
			n:    4,
		},
		{
			name: "8",
			n:    8,
		},
		{
			name: "16",
			n:    16,
		},
		{
			name: "17",
			n:    17,
		},
		{
			name: "32",
			n:    32,
		},
		{
			name: "64",
			n:    64,
		},
		{
			name: "128",
			n:    128,
		},
		{
			name: "1 << 8",
			n:    1 << 8,
		},
		{
			name: "1 << 9",
			n:    1 << 9,
		},
		{
			name: "1 << 10",
			n:    1 << 10,
		},
		{
			name: "1 << 11",
			n:    1 << 11,
		},
		{
			name: "1 << 12",
			n:    1 << 12,
		},
		{
			name: "1 << 13",
			n:    1 << 13,
		},
		{
			name: "1 << 14",
			n:    1 << 14,
		},
		{
			name: "1 << 15",
			n:    1 << 15,
		},
		{
			name: "1 << 16",
			n:    1 << 16,
		},
	}
	rand.Seed(time.Now().Unix())

	for _, vtt := range tests {
		tt := vtt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			done := make(chan interface{})
			go func() {
				defer close(done)

				it, err := newRangeIterator(int64(tt.n))
				require.NoError(t, err)
				bitset := big.NewInt(0)
				cnt := 0
				for {
					cnt++
					i := int(it.Int().Int64())
					if bitset.Bit(i) == 1 {
						require.Fail(t, "number has already been visited",
							"number %d, P = %+v G = %+v startI = %+v", i, it.P, it.G, it.startI)
					}
					bitset.SetBit(bitset, i, 1)
					if !it.Next() {
						break
					}
				}
				for i := 1; i <= tt.n; i++ {
					require.Equal(t, uint(1), bitset.Bit(i),
						"number %d is not visited, P = %+v G = %+v startI = %+v", i, it.P, it.G, it.startI)
				}
				require.Equal(t, tt.n, cnt, "count is not valid")
				require.False(t, it.Next())
			}()
			waitDone(t, done)
		})
	}
}

func BenchmarkRangeIterator(b *testing.B) {
	b.ReportAllocs()
	it, err := newRangeIterator(int64(b.N))
	require.NoError(b, err)
	for {
		if !it.Next() {
			break
		}
	}
}
