package arp

import (
	"context"
	"fmt"
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

type cacheReqGenerator struct {
	reqgen scan.RequestGenerator
	getMAC func(net.IP) net.HardwareAddr
}

func NewCacheRequestGenerator(reqgen scan.RequestGenerator, gatewayIP net.IP, cache *Cache) scan.RequestGenerator {
	result := &cacheReqGenerator{reqgen: reqgen}
	if gatewayIP == nil {
		result.getMAC = func(ip net.IP) net.HardwareAddr {
			return cache.Get(ip)
		}
	} else {
		result.getMAC = func(net.IP) net.HardwareAddr {
			return cache.Get(gatewayIP)
		}
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
