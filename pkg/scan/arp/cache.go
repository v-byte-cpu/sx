package arp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/v-byte-cpu/sx/pkg/scan"
)

type Cache struct {
	cache map[string]net.HardwareAddr
	mu    sync.RWMutex
}

func NewCache() *Cache {
	return &Cache{cache: make(map[string]net.HardwareAddr)}
}

func (c *Cache) Put(ip net.IP, mac net.HardwareAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[ip.String()] = mac
}

func (c *Cache) Get(ip net.IP) net.HardwareAddr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache[ip.String()]
}

func (c *Cache) Delete(ip net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, ip.String())
}

func FillCache(cache *Cache, r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var entry ScanResult
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

type cacheReqGenerator struct {
	reqgen scan.RequestGenerator
	getMAC func(net.IP) net.HardwareAddr
}

func NewCacheRequestGenerator(reqgen scan.RequestGenerator, gatewayMAC net.HardwareAddr, cache *Cache) scan.RequestGenerator {
	result := &cacheReqGenerator{reqgen: reqgen}
	result.getMAC = func(ip net.IP) net.HardwareAddr {
		if mac := cache.Get(ip); mac != nil {
			return mac
		}
		return gatewayMAC
	}
	return result
}

func (g *cacheReqGenerator) GenerateRequests(ctx context.Context, r *scan.Range) (<-chan *scan.Request, error) {
	requests, err := g.reqgen.GenerateRequests(ctx, r)
	if err != nil {
		return nil, err
	}
	result := make(chan *scan.Request, cap(requests))
	go func() {
		defer close(result)
		for request := range requests {
			if mac := g.getMAC(request.DstIP); mac != nil {
				request.DstMAC = mac
			} else {
				request.Err = fmt.Errorf("no destination MAC address for %s", request.DstIP)
			}
			result <- request
		}
	}()
	return result, nil
}
