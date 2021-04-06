package command

import (
	"bufio"
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
		if len(cliExitDelayFlag) > 0 {
			if cliExitDelay, err = time.ParseDuration(cliExitDelayFlag); err != nil {
				return
			}
		}
		return
	},
}

var (
	cliJSONFlag         bool
	cliInterfaceFlag    string
	cliSrcIPFlag        string
	cliSrcMACFlag       string
	cliPortsFlag        string
	cliRateLimitFlag    string
	cliExitDelayFlag    string
	cliARPCacheFileFlag string
	cliIPPortFileFlag   string
	cliProtoFlag        string

	cliInterface  *net.Interface
	cliSrcIP      net.IP
	cliSrcMAC     net.HardwareAddr
	cliPortRanges []*scan.PortRange
	cliDstSubnet  *net.IPNet
	cliRateCount  int
	cliRateWindow time.Duration
	cliExitDelay  = 300 * time.Millisecond
)

const (
	cliHTTPProtoFlag  = "http"
	cliHTTPSProtoFlag = "https"
)

var (
	errSrcIP        = errors.New("invalid source IP")
	errSrcMAC       = errors.New("invalid source MAC")
	errSrcInterface = errors.New("invalid source interface")
	errRateLimit    = errors.New("invalid ratelimit")
	errStdin        = errors.New("stdin is from a terminal")
)

func init() {
	rootCmd.PersistentFlags().BoolVar(&cliJSONFlag, "json", false, "enable JSON output")
	rootCmd.PersistentFlags().StringVarP(&cliInterfaceFlag, "iface", "i", "", "set interface to send/receive packets")
	rootCmd.PersistentFlags().StringVar(&cliSrcIPFlag, "srcip", "", "set source IP address for generated packets")
	rootCmd.PersistentFlags().StringVar(&cliSrcMACFlag, "srcmac", "", "set source MAC address for generated packets")
	rootCmd.PersistentFlags().StringVarP(&cliRateLimitFlag, "rate", "r", "",
		strings.Join([]string{
			"set rate limit for generated packets",
			`format: "rateCount/rateWindow"`,
			"where rateCount is a number of packets, rateWindow is the time interval",
			"e.g. 1000/s -- 1000 packets per second", "500/7s -- 500 packets per 7 seconds\n"}, "\n"))
	rootCmd.PersistentFlags().StringVar(&cliExitDelayFlag, "exit-delay", "",
		strings.Join([]string{
			"set exit delay to wait for response packets",
			"any expression accepted by time.ParseDuration is valid (300ms by default)"}, "\n"))
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

	var cache *arp.Cache
	if cache, err = parseARPCache(); err != nil {
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

func parseARPCache() (cache *arp.Cache, err error) {
	var r io.Reader
	if len(cliARPCacheFileFlag) > 0 {
		var f *os.File
		if f, err = os.Open(cliARPCacheFileFlag); err != nil {
			return
		}
		defer f.Close()
		r = bufio.NewReader(f)
	} else {
		var info os.FileInfo
		if info, err = os.Stdin.Stat(); err != nil {
			return
		}
		// only data being piped to stdin is valid
		if (info.Mode() & os.ModeCharDevice) != 0 {
			// stdin from terminal is not valid
			return nil, errStdin
		}
		r = os.Stdin
	}
	cache = arp.NewCache()
	err = arp.FillCache(cache, r)
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

func newIPPortGenerator() (reqgen scan.RequestGenerator) {
	if len(cliIPPortFileFlag) == 0 {
		return scan.NewIPPortGenerator(scan.NewIPGenerator(), scan.NewPortGenerator())
	}
	if len(cliPortRanges) == 0 {
		return scan.NewFileIPPortGenerator(func() (io.ReadCloser, error) {
			return os.Open(cliIPPortFileFlag)
		})
	}
	ipgen := scan.NewFileIPGenerator(func() (io.ReadCloser, error) {
		return os.Open(cliIPPortFileFlag)
	})
	return scan.NewIPPortGenerator(ipgen, scan.NewPortGenerator())
}

type bpfFilterFunc func(r *scan.Range) (filter string, maxPacketLength int)

type engineConfig struct {
	logger     log.Logger
	scanRange  *scan.Range
	rateCount  int
	rateWindow time.Duration
	exitDelay  time.Duration
}

type engineConfigOption func(c *engineConfig)

func withLogger(logger log.Logger) engineConfigOption {
	return func(c *engineConfig) {
		c.logger = logger
	}
}

func withScanRange(r *scan.Range) engineConfigOption {
	return func(c *engineConfig) {
		c.scanRange = r
	}
}

func newEngineConfig(opts ...engineConfigOption) *engineConfig {
	c := &engineConfig{
		rateCount:  cliRateCount,
		rateWindow: cliRateWindow,
		exitDelay:  cliExitDelay,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

type packetScanConfig struct {
	*engineConfig
	scanMethod scan.PacketMethod
	bpfFilter  bpfFilterFunc
}

type packetScanConfigOption func(c *packetScanConfig)

func withPacketEngineConfig(conf *engineConfig) packetScanConfigOption {
	return func(c *packetScanConfig) {
		c.engineConfig = conf
	}
}

func withPacketScanMethod(sm scan.PacketMethod) packetScanConfigOption {
	return func(c *packetScanConfig) {
		c.scanMethod = sm
	}
}

func withPacketBPFFilter(bpfFilter bpfFilterFunc) packetScanConfigOption {
	return func(c *packetScanConfig) {
		c.bpfFilter = bpfFilter
	}
}

func newPacketScanConfig(opts ...packetScanConfigOption) *packetScanConfig {
	c := &packetScanConfig{}
	for _, o := range opts {
		o(c)
	}
	return c
}

func startPacketScanEngine(ctx context.Context, conf *packetScanConfig) error {
	r := conf.scanRange

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
	engine := scan.SetupPacketEngine(rw, conf.scanMethod)
	return startScanEngine(ctx, engine, conf.engineConfig)
}

func startScanEngine(ctx context.Context, engine scan.EngineResulter, conf *engineConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	logger := conf.logger

	// setup result logging
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.LogResults(ctx, engine.Results())
	}()

	// start scan
	done, errc := engine.Start(ctx, conf.scanRange)
	go func() {
		defer cancel()
		<-done
		<-time.After(conf.exitDelay)
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
