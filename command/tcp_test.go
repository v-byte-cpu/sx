package command

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseTCPFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "EmptyFlags",
			input:    "",
			expected: []string{},
		},
		{
			name:     "SynFlag",
			input:    "syn",
			expected: []string{"syn"},
		},
		{
			name:     "AckFlag",
			input:    "ack",
			expected: []string{"ack"},
		},
		{
			name:     "FinFlag",
			input:    "fin",
			expected: []string{"fin"},
		},
		{
			name:     "RstFlag",
			input:    "rst",
			expected: []string{"rst"},
		},
		{
			name:     "PshFlag",
			input:    "psh",
			expected: []string{"psh"},
		},
		{
			name:     "UrgFlag",
			input:    "urg",
			expected: []string{"urg"},
		},
		{
			name:     "EceFlag",
			input:    "ece",
			expected: []string{"ece"},
		},
		{
			name:     "CwrFlag",
			input:    "cwr",
			expected: []string{"cwr"},
		},
		{
			name:     "NsFlag",
			input:    "ns",
			expected: []string{"ns"},
		},
		{
			name:     "SynAckFlag",
			input:    "syn,ack",
			expected: []string{"syn", "ack"},
		},
		{
			name:     "AckFinFlag",
			input:    "ack,fin",
			expected: []string{"ack", "fin"},
		},
		{
			name:     "CwrNsFlag",
			input:    "cwr,ns",
			expected: []string{"cwr", "ns"},
		},
		{
			name:     "AllFlags",
			input:    "syn,ack,fin,rst,psh,urg,ece,cwr,ns",
			expected: []string{"syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr", "ns"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseTCPFlags(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestParseTCPFlagsError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "OneInvalidFlag",
			input: "abc",
		},
		{
			name:  "OneValidAndInvalidFlag",
			input: "syn,abc",
		},
		{
			name:  "TwoValidAndInvalidFlag",
			input: "syn,abc,ack",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseTCPFlags(tt.input)
			require.Error(t, err)
		})
	}
}
