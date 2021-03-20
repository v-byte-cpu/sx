package command

import (
	"bufio"
	"context"
	"errors"
	"io"
	golog "log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
	"github.com/v-byte-cpu/sx/pkg/scan/tcpsyn"
)

var tcpPortsFlag string

func init() {
	tcpsynCmd.Flags().StringVarP(&tcpPortsFlag, "ports", "p", "", "set ports to scan")
	if err := tcpsynCmd.MarkFlagRequired("ports"); err != nil {
		golog.Fatalln(err)
	}
	rootCmd.AddCommand(tcpsynCmd)
}

var tcpsynCmd = &cobra.Command{
	Use:     "tcp [flags] subnet",
	Example: strings.Join([]string{"tcp -p 22 192.168.0.1/24", "tcp -p 22-4567 10.0.0.1"}, "\n"),
	Short:   "Perform TCP SYN scan",
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
		if r.StartPort, r.EndPort, err = parsePortRange(tcpPortsFlag); err != nil {
			return err
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		var logger log.Logger
		if logger, err = getLogger("tcpsyn", os.Stdout); err != nil {
			return err
		}

		// TODO file argument
		// TODO handle pipes
		cache := arp.NewCache()
		if err = fillARPCache(cache, os.Stdin); err != nil {
			return err
		}

		var gatewayIP net.IP
		if gatewayIP, err = getGatewayIP(r); err != nil {
			return err
		}
		m := getTCPSYNScanMethod(ctx, gatewayIP, cache)

		return startEngine(ctx, &engineConfig{
			logger:     logger,
			scanRange:  r,
			scanMethod: m,
			bpfFilter:  tcpsyn.BPFFilter,
		})
	},
}

// TODO port ranges with tests
func parsePortRange(portsRange string) (startPort, endPort uint16, err error) {
	ports := strings.Split(portsRange, "-")
	var port uint64
	if port, err = strconv.ParseUint(ports[0], 10, 16); err != nil {
		return
	}
	startPort = uint16(port)
	if len(ports) < 2 {
		endPort = startPort
		return
	}
	if port, err = strconv.ParseUint(ports[1], 10, 16); err != nil {
		return
	}
	endPort = uint16(port)
	return
}

// TODO move to arp package with tests
func fillARPCache(cache *arp.Cache, r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var entry arp.ScanResult
		if err := entry.UnmarshalJSON(scanner.Bytes()); err != nil {
			return err
		}
		ip := net.ParseIP(entry.IP)
		if ip == nil {
			return errors.New("invalid IP")
		}
		mac, err := net.ParseMAC(entry.MAC)
		if err != nil {
			return err
		}
		cache.Put(ip, mac)
	}
	return scanner.Err()
}

func getTCPSYNScanMethod(ctx context.Context, gatewayIP net.IP, cache *arp.Cache) *tcpsyn.ScanMethod {
	reqgen := arp.NewCacheRequestGenerator(
		scan.RequestGeneratorFunc(scan.Requests), gatewayIP, cache)
	pktgen := scan.NewPacketMultiGenerator(tcpsyn.NewPacketFiller(), runtime.NumCPU())
	psrc := scan.NewPacketSource(reqgen, pktgen)
	return tcpsyn.NewScanMethod(ctx, psrc)
}
