package command

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
	"github.com/v-byte-cpu/sx/pkg/scan/icmp"
)

var (
	cliICMPTypeFlag    string
	cliICMPCodeFlag    string
	cliICMPPayloadFlag string

	cliICMPType    uint8
	cliICMPCode    uint8
	cliICMPPayload []byte
)

func init() {
	icmpCmd.Flags().StringVar(&cliIPTTLFlag, "ttl", "",
		strings.Join([]string{"set IP TTL field of generated packet", "64 by default"}, "\n"))
	icmpCmd.Flags().StringVar(&cliIPTotalLenFlag, "iplen", "",
		strings.Join([]string{"set IP Total Length field of generated packet", "calculated by default"}, "\n"))
	icmpCmd.Flags().StringVar(&cliIPProtocolFlag, "ipproto", "",
		strings.Join([]string{"set IP Protocol field of generated packet", "1 (ICMP) by default"}, "\n"))
	icmpCmd.Flags().StringVar(&cliIPFlagsFlag, "ipflags", "",
		strings.Join([]string{"set IP Flags field of generated packet", "DF by default"}, "\n"))

	icmpCmd.Flags().StringVarP(&cliICMPTypeFlag, "type", "t", "",
		strings.Join([]string{"set ICMP type of generated packet", "ICMP Echo (Type 8) by default"}, "\n"))
	icmpCmd.Flags().StringVarP(&cliICMPCodeFlag, "code", "c", "",
		strings.Join([]string{"set ICMP code of generated packet", "0 by default"}, "\n"))
	icmpCmd.Flags().StringVarP(&cliICMPPayloadFlag, "payload", "p", "",
		strings.Join([]string{"set byte payload of generated packet", "48 random bytes by default"}, "\n"))

	icmpCmd.Flags().StringVarP(&cliARPCacheFileFlag, "arp-cache", "a", "",
		strings.Join([]string{"set ARP cache file", "reads from stdin by default"}, "\n"))
	rootCmd.AddCommand(icmpCmd)
}

var icmpCmd = &cobra.Command{
	Use: "icmp [flags] subnet",
	Example: strings.Join([]string{
		"icmp 192.168.0.1/24",
		"icmp --ttl 37 192.168.0.1/24",
		"icmp --ipproto 157 192.168.0.1/24",
		`icmp --type 13 --code 0 --payload '\x01\x02\x03' 10.0.0.1`}, "\n"),
	Short: "Perform ICMP scan",
	PreRunE: func(cmd *cobra.Command, args []string) (err error) {
		if len(args) != 1 {
			return errors.New("requires one ip subnet argument")
		}
		var icmpType uint64
		if len(cliICMPTypeFlag) > 0 {
			if icmpType, err = strconv.ParseUint(cliICMPTypeFlag, 10, 8); err != nil {
				return
			}
			cliICMPType = uint8(icmpType)
		}
		var icmpCode uint64
		if len(cliICMPCodeFlag) > 0 {
			if icmpCode, err = strconv.ParseUint(cliICMPCodeFlag, 10, 8); err != nil {
				return
			}
			cliICMPCode = uint8(icmpCode)
		}
		if len(cliICMPPayloadFlag) > 0 {
			if cliICMPPayload, err = parsePacketPayload(cliICMPPayloadFlag); err != nil {
				return
			}
		}
		return
	},
	RunE: func(cmd *cobra.Command, args []string) (err error) {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		var conf *scanConfig
		if conf, err = parseScanConfig(icmp.ScanType, args[0]); err != nil {
			return
		}

		m := newICMPScanMethod(ctx, conf)

		return startPacketScanEngine(ctx, newPacketScanConfig(
			withPacketScanMethod(m),
			withPacketBPFFilter(icmp.BPFFilter),
			withPacketEngineConfig(newEngineConfig(
				withLogger(conf.logger),
				withScanRange(conf.scanRange),
			)),
		))
	},
}

func newICMPScanMethod(ctx context.Context, conf *scanConfig) *icmp.ScanMethod {
	reqgen := arp.NewCacheRequestGenerator(
		scan.NewIPRequestGenerator(scan.NewIPGenerator()), conf.gatewayIP, conf.cache)
	pktgen := scan.NewPacketMultiGenerator(icmp.NewPacketFiller(getICMPOptions()...), runtime.NumCPU())
	psrc := scan.NewPacketSource(reqgen, pktgen)
	results := scan.NewResultChan(ctx, 1000)
	return icmp.NewScanMethod(psrc, results)
}

func getICMPOptions() (opts []icmp.PacketFillerOption) {
	if len(cliIPTTLFlag) > 0 {
		opts = append(opts, icmp.WithTTL(cliTTL))
	}
	if len(cliIPTotalLenFlag) > 0 {
		opts = append(opts, icmp.WithIPTotalLength(cliIPTotalLen))
	}
	if len(cliIPProtocolFlag) > 0 {
		opts = append(opts, icmp.WithIPProtocol(cliIPProtocol))
	}
	if len(cliIPFlagsFlag) > 0 {
		opts = append(opts, icmp.WithIPFlags(cliIPFlags))
	}
	if len(cliICMPTypeFlag) > 0 {
		opts = append(opts, icmp.WithType(cliICMPType))
	}
	if len(cliICMPCodeFlag) > 0 {
		opts = append(opts, icmp.WithCode(cliICMPCode))
	}
	if len(cliICMPPayloadFlag) > 0 {
		opts = append(opts, icmp.WithPayload(cliICMPPayload))
	}
	return
}
