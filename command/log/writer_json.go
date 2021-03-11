package log

import (
	"fmt"
	"io"

	"github.com/v-byte-cpu/sx/pkg/scan/arp"
)

type JSONResultWriter struct{}

func (*JSONResultWriter) Write(w io.Writer, result *arp.ScanResult) error {
	data, err := result.MarshalJSON()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s\n", data)
	return nil
}
