// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import "testing"

// TestServiceFlagStringer tests the stringized output for service flag types.
func TestServiceFlagStringer(t *testing.T) {
	tests := []struct {
		in   ServiceFlag
		want string
	}{
		{0, "0x0"},
		{SFNodeNetwork, "SFNodeNetwork"},
		{SFNodeGetUTXO, "SFNodeGetUTXO"},
		{SFNodeBloom, "SFNodeBloom"},
		{SFNodeWitness, "SFNodeWitness"},
		{SFNodeXthin, "SFNodeXthin"},
		{SFNodeBitcoinCash, "SFNodeBitcoinCash"},
		{SFNodeGraphene, "SFNodeGraphene"},
		{SFNodeWeakBlocks, "SFNodeWeakBlocks"},
		{SFNodeCF, "SFNodeCF"},
		{SFNodeXThinner, "SFNodeXThinner"},
		{SFNodeNetworkLimited, "SFNodeNetworkLimited"},
		{0xffffffff, "SFNodeNetwork|SFNodeGetUTXO|SFNodeBloom|SFNodeWitness|SFNodeXthin|SFNodeBitcoinCash|SFNodeGraphene|SFNodeWeakBlocks|SFNodeCF|SFNodeXThinner|SFNodeNetworkLimited|0xfffff800"},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		result := test.in.String()
		if result != test.want {
			t.Errorf("String #%d\n got: %s want: %s", i, result,
				test.want)
			continue
		}
	}
}

// TestBitcoinNetStringer tests the stringized output for bitcoin net types.
func TestBitcoinNetStringer(t *testing.T) {
	tests := []struct {
		in   BitcoinNet
		want string
	}{
		{MainNet, "MainNet"},
		{RegTestNet, "RegTest"},
		{TestNet, "TestNet"},
		{0xffffffff, "Unknown BitcoinNet (4294967295)"},
	}

	t.Logf(runningTestsFmt, len(tests))

	for i, test := range tests {
		result := test.in.String()
		if result != test.want {
			t.Errorf("String #%d\n got: %s want: %s", i, result,
				test.want)
			continue
		}
	}
}
