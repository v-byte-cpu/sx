package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		version  string
		commit   string
		expected string
	}{
		{
			name:     "VersionOnly",
			version:  "0.1.0",
			expected: "0.1.0",
		},
		{
			name:     "VersionAndCommit",
			version:  "0.1.0",
			commit:   "1234567",
			expected: "0.1.0\ncommit: 1234567",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildVersion(tt.version, tt.commit)
			require.Equal(t, tt.expected, result)
		})
	}
}
