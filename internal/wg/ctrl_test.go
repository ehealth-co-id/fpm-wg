package wg

import (
	"net/netip"
	"testing"
)

func TestPrefixIPNetRoundTrip(t *testing.T) {
	cases := []string{
		"192.168.200.3/32",
		"192.168.0.0/24",
		"10.255.0.3/32",
		"0.0.0.0/0",
		"2001:db8::/32",
		"fd00::1/128",
	}
	for _, s := range cases {
		want := netip.MustParsePrefix(s)
		got, ok := fromIPNet(toIPNet(want))
		if !ok {
			t.Fatalf("%s: conversion failed", s)
		}
		if got != want {
			t.Errorf("round trip %s -> %s", want, got)
		}
	}
}
