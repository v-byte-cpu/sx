package docker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/docker/docker/api/types"
	moby "github.com/moby/moby/client"
	"github.com/v-byte-cpu/sx/pkg/scan"
)

const (
	ScanType = "docker"

	defaultDataTimeout = 10 * time.Second
)

type ScanResult struct {
	ScanType string        `json:"scan"`
	Proto    string        `json:"proto"`
	Host     string        `json:"host"`
	Info     types.Info    `json:"info"`
	Version  types.Version `json:"version"`
}

func (r *ScanResult) String() string {
	return fmt.Sprintf("%s %s %s %s %s %s", r.Proto, r.Host, r.Info.Name,
		r.Info.OperatingSystem, r.Info.KernelVersion, r.Info.Architecture)
}

func (r *ScanResult) ID() string {
	return r.Host
}

func (r *ScanResult) MarshalJSON() ([]byte, error) {
	// Type definition for the recursive call
	type JScanResult ScanResult
	// This works because JScanResult doesn't have a MarshalJSON function associated with it
	return json.Marshal(JScanResult(*r))
}

type Scanner struct {
	client      *http.Client
	proto       string
	dataTimeout time.Duration
}

// Assert that docker.Scanner conforms to the scan.Scanner interface
var _ scan.Scanner = (*Scanner)(nil)

type ScannerOption func(*Scanner)

func WithDataTimeout(timeout time.Duration) ScannerOption {
	return func(s *Scanner) {
		s.dataTimeout = timeout
	}
}

func NewScanner(proto string, opts ...ScannerOption) *Scanner {
	tr := &http.Transport{
		MaxConnsPerHost:   1,
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	s := &Scanner{
		client: &http.Client{
			Transport: tr,
		},
		proto:       proto,
		dataTimeout: defaultDataTimeout,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Scanner) Scan(ctx context.Context, r *scan.Request) (result scan.Result, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.dataTimeout)
	defer cancel()
	// TODO DNS names
	host := fmt.Sprintf("tcp://%s:%d", r.DstIP.String(), r.DstPort)

	var docker *moby.Client
	if docker, err = moby.NewClientWithOpts(
		moby.WithAPIVersionNegotiation(),
		moby.WithHTTPClient(s.client),
		moby.WithScheme(s.proto),
		moby.WithHost(host),
	); err != nil {
		return
	}

	var info types.Info
	if info, err = docker.Info(ctx); err != nil {
		return
	}
	// retrieve server version ignoring error
	version, _ := docker.ServerVersion(ctx)
	result = &ScanResult{
		ScanType: ScanType,
		Proto:    s.proto,
		Host:     host,
		Info:     info,
		Version:  version,
	}
	return
}
