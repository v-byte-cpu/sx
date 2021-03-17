package log

import (
	"fmt"
	"io"

	"github.com/v-byte-cpu/sx/pkg/scan"
)

type JSONResultWriter struct{}

func (*JSONResultWriter) Write(w io.Writer, result scan.Result) error {
	data, err := result.MarshalJSON()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s\n", data)
	return nil
}
