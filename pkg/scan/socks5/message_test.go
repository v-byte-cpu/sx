package socks5

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteMethodRequest(t *testing.T) {
	tests := []struct {
		name     string
		request  *MethodRequest
		expected []byte
	}{
		{
			name:     "oneMethod",
			request:  NewMethodRequest(5, 0),
			expected: []byte{5, 1, 0},
		},
		{
			name:     "twoMethods",
			request:  NewMethodRequest(5, 0, 2),
			expected: []byte{5, 2, 0, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, err := tt.request.WriteTo(&buf)
			require.NoError(t, err)
			require.Equal(t, tt.expected, buf.Bytes())
		})
	}
}

func TestReadMethodReply(t *testing.T) {
	tests := []struct {
		name     string
		reply    []byte
		expected *MethodReply
	}{
		{
			name:     "SOCKS5version",
			reply:    []byte{SOCKSVersion, 0},
			expected: &MethodReply{Ver: SOCKSVersion, Method: 0},
		},
		{
			name:     "SOCKS4version",
			reply:    []byte{4, 91},
			expected: &MethodReply{Ver: 4, Method: 91},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, err := buf.Write(tt.reply)
			require.NoError(t, err)

			reply := &MethodReply{}
			_, err = reply.ReadFrom(&buf)
			require.NoError(t, err)

			require.Equal(t, tt.expected, reply)
		})
	}
}
