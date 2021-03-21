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
	"github.com/v-byte-cpu/sx/pkg/packet/afpacket"
	"github.com/v-byte-cpu/sx/pkg/scan"
	"github.com/v-byte-cpu/sx/pkg/scan/arp"
)

var rootCmd = &cobra.Command{
	Use:     "sx",
	Short:   "Fast, modern, easy-to-use network scanner",
	Version: "0.1.0",
}

var (
	jsonFlag      bool
	interfaceFlag string
	srcIPFlag     string
	srcMACFlag    string
	portsFlag     string
)

var (
	errSrcIP        = errors.New("invalid source IP")
	errSrcMAC       = errors.New("invalid source MAC")
	errSrcInterface = errors.New("invalid source interface")
)

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "enable JSON output")
	rootCmd.PersistentFlags().StringVarP(&interfaceFlag, "iface", "i", "", "set interface to send/receive packets")
	rootCmd.PersistentFlags().StringVar(&srcIPFlag, "srcip", "", "set source IP address for generated packets")
	rootCmd.PersistentFlags().StringVar(&srcMACFlag, "srcmac", "", "set source MAC address for generated packets")
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

func parseScanConfig(scanName, subnet, ports string) (c *scanConfig, err error) {
	var r *scan.Range
	if r, err = parseScanRange(subnet); err != nil {
		return
	}
	if r.StartPort, r.EndPort, err = parsePortRange(ports); err != nil {
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
	if len(srcIPFlag) > 0 {
		srcIP = net.ParseIP(srcIPFlag)
	}
	if srcIP == nil {
		return nil, errSrcIP
	}

	srcMAC := iface.HardwareAddr
	if len(srcMACFlag) > 0 {
		if srcMAC, err = net.ParseMAC(srcMACFlag); err != nil {
			return nil, err
		}
	}
	if srcMAC == nil {
		return nil, errSrcMAC
	}

	return &scan.Range{
		Interface: iface,
		DstSubnet: dstSubnet,
		SrcSubnet: srcSubnet,
		SrcIP:     srcIP.To4(),
		SrcMAC:    srcMAC}, nil
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

func getSubnetInterface(dstSubnet *net.IPNet) (iface *net.Interface, srcSubnet *net.IPNet, err error) {
	if len(interfaceFlag) == 0 {
		return ip.GetSubnetInterface(dstSubnet)
	}
	if iface, err = net.InterfaceByName(interfaceFlag); err != nil {
		return
	}
	if srcSubnet, err = ip.GetSubnetInterfaceIP(iface, dstSubnet); err != nil {
		return
	}
	return iface, srcSubnet, nil
}

func getLogger(name string, w io.Writer) (logger log.Logger, err error) {
	opts := []log.LoggerOption{log.FlushInterval(1 * time.Second)}
	if jsonFlag {
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
	rw, err := afpacket.NewPacketSource(r.Interface.Name)
	if err != nil {
		return err
	}
	defer rw.Close()
	err = rw.SetBPFFilter(conf.bpfFilter(r))
	if err != nil {
		return err
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
