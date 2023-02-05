//go:build darwin || dragonfly || freebsd || netbsd || openbsd
// +build darwin dragonfly freebsd netbsd openbsd

package afpacket

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/bsdbpf"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/unix"
	"reflect"
	"syscall"
	"unsafe"
)

type Source struct {
	handle        *bsdbpf.BPFSniffer
	handleOptions *bsdbpf.Options
	handleFd      int
	linkType      layers.LinkType
}

func NewPacketSource(iface string) (*Source, error) {
	options := bsdbpf.Options{
		Promisc:          true,
		Immediate:        true,
		PreserveLinkAddr: true,
	}

	handle, err := bsdbpf.NewBPFSniffer(iface, &options)
	if err != nil {
		return nil, err
	}

	/*
	* BPFSniffer does not provide API to set BPF Filter, moreover it does not allow to access BPF device fd.
	* Therefore, in order to do not duplicate the code, it requires a bit of dark magic
	 */

	rs := reflect.ValueOf(handle).Elem()
	rf := rs.Field(2) // BPFSniffer.fd is the 3rd field
	rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()
	f := rf.Interface()
	val := reflect.ValueOf(f)
	fd := int(val.Int())

	// Locally generated packets on the interface should not be returned by BPF.
	err = unix.IoctlSetPointerInt(fd, syscall.BIOCSSEESENT, 0)
	if err != nil {
		goto errlbl
	}

	return &Source{handle, &options, fd, layers.LinkTypeEthernet}, nil
errlbl:
	handle.Close()
	return nil, err
}

func (s *Source) SetBPFFilter(bpfFilter string, maxPacketLength int) error {
	pcapBPF, err := pcap.CompileBPFFilter(s.linkType, maxPacketLength, bpfFilter)
	if err != nil {
		return err
	}

	bpfIns := make([]syscall.BpfInsn, 0, len(pcapBPF))
	for _, ins := range pcapBPF {
		sysIns := syscall.BpfInsn{
			Code: ins.Code,
			Jt:   ins.Jt,
			Jf:   ins.Jf,
			K:    ins.K,
		}
		bpfIns = append(bpfIns, sysIns)
	}

	return syscall.SetBpf(s.handleFd, bpfIns)
}

func (s *Source) Close() {
	s.handle.Close()
}

func (s *Source) ReadPacketData() ([]byte, *gopacket.CaptureInfo, error) {
	data, ci, err := s.handle.ReadPacketData()
	return data, &ci, err
}

func (s *Source) WritePacketData(pkt []byte) error {
	_, err := unix.Write(s.handleFd, pkt)
	return err
}
