package log

import (
	"fmt"
	"io"

	"github.com/v-byte-cpu/sx/pkg/scan/arp"
)

type PlainResultWriter struct{}

func (*PlainResultWriter) Write(w io.Writer, result *arp.ScanResult) error {
	_, err := fmt.Fprintf(w, "%s\n", result.String())
	return err
}
