package auth

import (
	"fmt"
	"net"
	"strings"
)

type NASIPValidator struct {
	allowedNetworks []*net.IPNet
	allowedIPs      map[string]struct{}
}

func NewNASIPValidator(ipRanges []string) (*NASIPValidator, error) {
	validator := &NASIPValidator{
		allowedNetworks: make([]*net.IPNet, 0),
		allowedIPs:      make(map[string]struct{}),
	}

	for _, ipRange := range ipRanges {
		if strings.Contains(ipRange, "/") {
			_, ipNet, err := net.ParseCIDR(ipRange)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR: %s: %w", ipRange, err)
			}
			validator.allowedNetworks = append(validator.allowedNetworks, ipNet)
		} else {
			ip := net.ParseIP(ipRange)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %s", ipRange)
			}
			validator.allowedIPs[ip.String()] = struct{}{}
		}
	}

	return validator, nil
}

func (v *NASIPValidator) IsAllowed(ip net.IP) bool {
	if _, exists := v.allowedIPs[ip.String()]; exists {
		return true
	}

	for _, network := range v.allowedNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
