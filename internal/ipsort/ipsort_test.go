package ipsort_test

import (
	"math"
	"testing"

	"layzmd/internal/ipsort"
)

func TestKeyOrdering(t *testing.T) {
	// Octet-level ordering: .2 < .10 (not lexicographic)
	if !(ipsort.Key("10.0.0.2") < ipsort.Key("10.0.0.10")) {
		t.Errorf("Key(10.0.0.2) should be < Key(10.0.0.10)")
	}
	if !(ipsort.Key("10.0.0.9") < ipsort.Key("10.0.0.10")) {
		t.Errorf("Key(10.0.0.9) should be < Key(10.0.0.10)")
	}
}

func TestKeyNonIP(t *testing.T) {
	// Non-IP values must sort last (>= any real IP key)
	maxVal := ipsort.Key("foo")
	if maxVal != math.MaxUint64 {
		t.Errorf("Key(\"foo\") = %d; want math.MaxUint64", maxVal)
	}
	// Also verify a real max IP is still less than MaxUint64
	realMax := ipsort.Key("255.255.255.255")
	if realMax >= math.MaxUint64 {
		t.Errorf("Key(255.255.255.255) should be < MaxUint64")
	}
	if maxVal < realMax {
		t.Errorf("non-IP key should be >= any real IP key")
	}
}
