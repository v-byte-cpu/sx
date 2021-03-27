package command

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/routing"
	"github.com/spf13/cobra"
	"github.com/v-byte-cpu/sx/command/log"
	"github.com/v-byte-cpu/sx/pkg/ip"
	"github.com/v-byte-cpu/sx/pkg/packet"
	"github.com/v-byte-cpu/sx/pkg/packet/afpacket"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
	"go.uber.org/ratelimit"
)

var rootCmd = &cobra.Command{
	Use:     "sx",
	Short:   "Fast, modern, easy-to-use network scanner",
	Version: "0.1.0",
	// Parse common flags
	PersistentPreRunE: func(cmd *cobra.Command, args []string) (err error) {
		if len(cliInterfaceFlag) > 0 {
			if cliInterface, err = net.InterfaceByName(cliInterfaceFlag); err != nil {
				return
			}
		}
		if len(cliSrcIPFlag) > 0 {
			if cliSrcIP = net.ParseIP(cliSrcIPFlag); cliSrcIP == nil {
				return errSrcIP
			}
		}
		if len(cliSrcMACFlag) > 0 {
			if cliSrcMAC, err = net.ParseMAC(cliSrcMACFlag); err != nil {
				return
			}
		}
		if len(cliPortsFlag) > 0 {
			if cliPortRanges, err = parsePortRanges(cliPortsFlag); err != nil {
				return
			}
		}
		if len(cliRateLimitFlag) > 0 {
			if cliRateCount, cliRateWindow, err = parseRateLimit(cliRateLimitFlag); err != nil {
				return
			}
		}
		return
	},
}

var (
	cliJSONFlag      bool
	cliInterfaceFlag string
	cliSrcIPFlag     string
	cliSrcMACFlag    string
	cliPortsFlag     string
	cliRateLimitFlag string

	cliInterface  *net.Interface
	cliSrcIP      net.IP
	cliSrcMAC     net.HardwareAddr
	cliPortRanges []*scan.PortRange
	cliRateCount  int
	cliRateWindow time.Duration
)

var (
	errSrcIP        = errors.New("invalid source IP")
	errSrcMAC       = errors.New("invalid source MAC")
	errSrcInterface = errors.New("invalid source interface")
	errRateLimit    = errors.New("invalid ratelimit")
)

func init() {
	rootCmd.PersistentFlags().BoolVar(&cliJSONFlag, "json", false, "enable JSON output")
	rootCmd.PersistentFlags().StringVarP(&cliInterfaceFlag, "iface", "i", "", "set interface to send/receive packets")
	rootCmd.PersistentFlags().StringVar(&cliSrcIPFlag, "srcip", "", "set source IP address for generated packets")
	rootCmd.PersistentFlags().StringVar(&cliSrcMACFlag, "srcmac", "", "set source MAC address for generated packets")
	rootCmd.PersistentFlags().StringVarP(&cliRateLimitFlag, "rate", "r", "", "set rate limit for generated packets")
}

func Main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

type scanConfig struct {
	logger    log.Logger
	scanRange *scan.Range
	cache     *arp.Cache
	gatewayIP net.IP
}

func parseScanConfig(scanName, subnet string) (c *scanConfig, err error) {
	var r *scan.Range
	if r, err = parseScanRange(subnet); err != nil {
		return
	}

	var logger log.Logger
	if logger, err = getLogger(scanName, os.Stdout); err != nil {
		return
	}

	// TODO file argument
	// TODO handle pipes
	cache := arp.NewCache()
	if err = arp.FillCache(cache, os.Stdin); err != nil {
		return
	}

	var gatewayIP net.IP
	if gatewayIP, err = getGatewayIP(r); err != nil {
		return
	}
	c = &scanConfig{
		logger:    logger,
		scanRange: r,
		cache:     cache,
		gatewayIP: gatewayIP,
	}
	return
}

func parseScanRange(subnet string) (*scan.Range, error) {
	dstSubnet, err := ip.ParseIPNet(subnet)
	if err != nil {
		return nil, err
	}
	iface, srcSubnet, err := getSubnetInterface(dstSubnet)
	if err != nil {
		return nil, err
	}
	if iface == nil || srcSubnet == nil {
		return nil, errSrcInterface
	}

	srcIP := srcSubnet.IP
	if cliSrcIP != nil {
		srcIP = cliSrcIP
	}
	if srcIP == nil {
		return nil, errSrcIP
	}

	srcMAC := iface.HardwareAddr
	if cliSrcMAC != nil {
		srcMAC = cliSrcMAC
	}
	if srcMAC == nil {
		return nil, errSrcMAC
	}

	return &scan.Range{
		Interface: iface,
		DstSubnet: dstSubnet,
		Ports:     cliPortRanges,
		SrcSubnet: srcSubnet,
		SrcIP:     srcIP.To4(),
		SrcMAC:    srcMAC}, nil
}

func parsePortRange(portsRange string) (r *scan.PortRange, err error) {
	ports := strings.Split(portsRange, "-")
	var port uint64
	if port, err = strconv.ParseUint(ports[0], 10, 16); err != nil {
		return
	}
	result := &scan.PortRange{StartPort: uint16(port), EndPort: uint16(port)}
	if len(ports) < 2 {
		return result, nil
	}
	if port, err = strconv.ParseUint(ports[1], 10, 16); err != nil {
		return
	}
	result.EndPort = uint16(port)
	return result, nil
}

func parsePortRanges(portsRanges string) (result []*scan.PortRange, err error) {
	var ports *scan.PortRange
	for _, portsRange := range strings.Split(portsRanges, ",") {
		if ports, err = parsePortRange(portsRange); err != nil {
			return
		}
		result = append(result, ports)
	}
	return
}

func parseRateLimit(rateLimit string) (rateCount int, rateWindow time.Duration, err error) {
	parts := strings.Split(rateLimit, "/")
	if len(parts) > 2 {
		return 0, 0, errRateLimit
	}
	var rate int64
	if rate, err = strconv.ParseInt(parts[0], 10, 32); err != nil || rate < 0 {
		return 0, 0, errRateLimit
	}
	rateCount = int(rate)
	rateWindow = 1 * time.Second
	if len(parts) < 2 {
		return
	}
	win := parts[1]
	if len(win) > 0 && (win[0] < '0' || win[0] > '9') {
		win = "1" + win
	}
	if rateWindow, err = time.ParseDuration(win); err != nil || rateWindow < 0 {
		return 0, 0, errRateLimit
	}
	return
}

func getSubnetInterface(dstSubnet *net.IPNet) (iface *net.Interface, srcSubnet *net.IPNet, err error) {
	if cliInterface == nil {
		return ip.GetSubnetInterface(dstSubnet)
	}
	if srcSubnet, err = ip.GetSubnetInterfaceIP(cliInterface, dstSubnet); err != nil {
		return
	}
	return iface, srcSubnet, nil
}

func getLogger(name string, w io.Writer) (logger log.Logger, err error) {
	opts := []log.LoggerOption{log.FlushInterval(1 * time.Second)}
	if cliJSONFlag {
		opts = append(opts, log.JSON())
	}
	logger, err = log.NewLogger(w, name, opts...)
	return
}

func getGatewayIP(r *scan.Range) (gatewayIP net.IP, err error) {
	var router routing.Router
	if router, err = routing.New(); err != nil {
		return
	}
	if _, gatewayIP, _, err = router.RouteWithSrc(
		r.Interface.HardwareAddr, r.SrcIP, r.DstSubnet.IP); err != nil {
		return
	}
	// if local address then don't need gateway
	if gatewayIP == nil || r.DstSubnet.Contains(gatewayIP) {
		return nil, nil
	}
	gatewayIP = gatewayIP.To4()
	return
}

type engineConfig struct {
	logger     log.Logger
	scanRange  *scan.Range
	scanMethod resultScanMethod
	bpfFilter  func(r *scan.Range) (filter string, maxPacketLength int)
	rateCount  int
	rateWindow time.Duration
}

type resultScanMethod interface {
	scan.Method
	Results() <-chan scan.Result
}

func startEngine(ctx context.Context, conf *engineConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	r := conf.scanRange
	m := conf.scanMethod
	logger := conf.logger

	// setup network interface to read/write packets
	afps, err := afpacket.NewPacketSource(r.Interface.Name)
	if err != nil {
		return err
	}
	defer afps.Close()
	err = afps.SetBPFFilter(conf.bpfFilter(r))
	if err != nil {
		return err
	}
	var rw packet.ReadWriter = afps
	// setup rate limit for sending packets
	if conf.rateCount > 0 {
		rw = packet.NewRateLimitReadWriter(afps,
			ratelimit.New(conf.rateCount, ratelimit.Per(conf.rateWindow)))
	}

	// setup result logging
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.LogResults(ctx, m.Results())
	}()

	// start scan
	engine := scan.SetupEngine(rw, m)
	done, errc := engine.Start(ctx, r)
	go func() {
		defer cancel()
		<-done
		<-time.After(300 * time.Millisecond)
	}()

	// error logging
	wg.Add(1)
	go func() {
		defer wg.Done()
		for err := range errc {
			logger.Error(err)
		}
	}()
	wg.Wait()
	return nil
}
