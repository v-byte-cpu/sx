//go:generate easyjson -output_filename result_easyjson.go elastic.go

package elastic

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/v-byte-cpu/sx/pkg/scan"
)

const (
	ScanType = "elastic"

	defaultDataTimeout = 5 * time.Second
)

//easyjson:json
type ScanResult struct {
	ScanType string                 `json:"scan"`
	Proto    string                 `json:"proto"`
	Host     string                 `json:"host"`
	Info     map[string]interface{} `json:"info"`
	Indexes  map[string]interface{} `json:"indexes"`
}

func (r *ScanResult) String() string {
	return fmt.Sprintf("%s://%s %s %d", r.Proto, r.Host, r.Info["cluster_name"], len(r.Indexes))
}

func (r *ScanResult) ID() string {
	return r.Host
}

type Scanner struct {
	elastic *elasticClient
	proto   string
}

// Assert that elastic.Scanner conforms to the scan.Scanner interface
var _ scan.Scanner = (*Scanner)(nil)

type ScannerOption func(*Scanner)

func WithDataTimeout(timeout time.Duration) ScannerOption {
	return func(s *Scanner) {
		s.elastic.dataTimeout = timeout
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
	ec := &elasticClient{
		client: &http.Client{
			Transport: tr,
		},
		proto:       proto,
		dataTimeout: defaultDataTimeout,
	}
	s := &Scanner{ec, proto}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Scanner) Scan(ctx context.Context, r *scan.Request) (result scan.Result, err error) {
	// TODO DNS names
	host := fmt.Sprintf("%s:%d", r.DstIP.String(), r.DstPort)
	// retrieve main info
	var info map[string]interface{}
	if info, err = s.elastic.GetInfo(ctx, host); err != nil {
		return
	}
	// retrieve all indexes with aliases ignoring error
	indexes, _ := s.elastic.GetIndexes(ctx, host)
	result = &ScanResult{
		ScanType: ScanType,
		Proto:    s.proto,
		Host:     host,
		Info:     info,
		Indexes:  indexes,
	}
	return
}

type elasticClient struct {
	client      *http.Client
	proto       string
	dataTimeout time.Duration
}

func (c *elasticClient) GetInfo(ctx context.Context, host string) (info map[string]interface{}, err error) {
	return c.Get(ctx, fmt.Sprintf("%s://%s/", c.proto, host))
}

func (c *elasticClient) GetIndexes(ctx context.Context, host string) (info map[string]interface{}, err error) {
	return c.Get(ctx, fmt.Sprintf("%s://%s/_aliases", c.proto, host))
}

func (c *elasticClient) Get(ctx context.Context, url string) (data map[string]interface{}, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.dataTimeout)
	defer cancel()
	var req *http.Request
	if req, err = http.NewRequestWithContext(ctx, "GET", url, nil); err != nil {
		return
	}
	var resp *http.Response
	if resp, err = c.client.Do(req); err != nil {
		return
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&data)
	return
}
