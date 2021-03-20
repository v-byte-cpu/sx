package command

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
)

var arpLiveModeFlag bool

func init() {
	arpCmd.Flags().BoolVar(&arpLiveModeFlag, "live", false, "enable live mode")
	rootCmd.AddCommand(arpCmd)
}

var arpCmd = &cobra.Command{
	Use:     "arp [flags] subnet",
	Example: strings.Join([]string{"arp 192.168.0.1/24", "arp 10.0.0.1"}, "\n"),
	Short:   "Perform ARP scan",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("requires one ip subnet argument")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		var r *scan.Range
		if r, err = parseScanRange(args[0]); err != nil {
			return err
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		var logger log.Logger
		if logger, err = getLogger("arp", os.Stdout); err != nil {
			return err
		}
		if arpLiveModeFlag {
			logger = log.NewUniqueLogger(logger)
		}

		m := newARPScanMethod(ctx)

		return startEngine(ctx, &engineConfig{
			logger:     logger,
			scanRange:  r,
			scanMethod: m,
			bpfFilter:  arp.BPFFilter,
		})
	},
}

func newARPScanMethod(ctx context.Context) *arp.ScanMethod {
	var reqgen scan.RequestGenerator = scan.RequestGeneratorFunc(scan.Requests)
	if arpLiveModeFlag {
		reqgen = scan.NewLiveRequestGenerator(1 * time.Second)
	}
	pktgen := scan.NewPacketMultiGenerator(arp.NewPacketFiller(), runtime.NumCPU())
	psrc := scan.NewPacketSource(reqgen, pktgen)
	return arp.NewScanMethod(ctx, psrc)
}
