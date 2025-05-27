package auth

import (
	"fmt"
	"net"
	"strings"
)

type NASIPValidator struct {
	allowedNetworks []*net.IPNet
	allowedIPs      []net.IP
}

func NewNASIPValidator(ipRanges []string) (*NASIPValidator, error) {
	validator := &NASIPValidator{
		allowedNetworks: make([]*net.IPNet, 0),
		allowedIPs:      make([]net.IP, 0),
	}

	for _, ipRange := range ipRanges {
		if strings.Contains(ipRange, "/") {
			// 处理 CIDR
			_, ipNet, err := net.ParseCIDR(ipRange)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR: %s: %w", ipRange, err)
			}
			validator.allowedNetworks = append(validator.allowedNetworks, ipNet)
		} else {
			// 处理单个IP
			ip := net.ParseIP(ipRange)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %s", ipRange)
			}
			validator.allowedIPs = append(validator.allowedIPs, ip)
		}
	}

	return validator, nil
}

func (v *NASIPValidator) IsAllowed(ip net.IP) bool {
	// 检查单个IP列表
	for _, allowedIP := range v.allowedIPs {
		if ip.Equal(allowedIP) {
			return true
		}
	}

	// 检查IP网段
	for _, network := range v.allowedNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
