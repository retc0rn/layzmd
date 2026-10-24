// Package ipsort provides a numeric sort key for IPv4 address strings.
package ipsort

import (
	"math"
	"strconv"
	"strings"
)

// Key returns a uint64 that preserves correct numeric IP ordering when compared.
// The value is (a<<24 | b<<16 | c<<8 | d) for a valid x.x.x.x address.
// Any input that is not a valid IPv4 address returns math.MaxUint64 so that
// invalid entries sort last.
func Key(ip string) uint64 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return math.MaxUint64
	}
	var octets [4]uint64
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return math.MaxUint64
		}
		octets[i] = uint64(n)
	}
	return octets[0]<<24 | octets[1]<<16 | octets[2]<<8 | octets[3]
}
