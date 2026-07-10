// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

// Package light holds the one copy of the public Lux "light" dev mnemonic and
// the wallet keys derived from it. Local networks only (network ID 1337, EVM
// chain ID 31337). The seed is public, so it must never back a real network;
// RefuseOnProduction enforces that. No staker, node ID, or BLS material lives
// here — validator keys are random per node and kept with each node.
package light

import "crypto/subtle"

// Mnemonic is the public Lux dev seed. Use it as LUX_MNEMONIC (or
// LIGHT_MNEMONIC) to boot a local network. Reference this const; never copy the
// literal.
const Mnemonic = "light light light light light light light light light light light energy"

// knownPublicMnemonics are the seeds anyone can derive from. RefuseOnProduction
// admits exactly these; anything else is treated as a real seed. Kept in sync
// with genesis' light_mnemonic_guard.
var knownPublicMnemonics = []string{
	Mnemonic,
	"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
	"legal winner thank year wave sausage worth useful legal winner thank yellow",
	"test test test test test test test test test test test junk",
	"witch collapse practice feed shame open despair creek road again ice least",
	"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
}

// IsLight reports whether s is the light Mnemonic, in constant time.
func IsLight(s string) bool {
	return subtle.ConstantTimeCompare([]byte(s), []byte(Mnemonic)) == 1
}

// isKnownPublic reports whether m is a known public seed. Every entry is
// compared, so the loop leaks neither which matched nor when.
func isKnownPublic(m string) bool {
	matched := false
	mb := []byte(m)
	for _, cand := range knownPublicMnemonics {
		if subtle.ConstantTimeCompare(mb, []byte(cand)) == 1 {
			matched = true
		}
	}
	return matched
}

// RefuseOnProduction returns an error for an empty seed or any seed that is not
// a known public one; a known public seed returns nil. It mirrors
// genesis.RefuseLightMnemonicOnProduction without the network coupling: the
// caller decides where it runs, this decides whether the seed is public.
func RefuseOnProduction(mnemonic string) error {
	if mnemonic == "" {
		return errEmptyMnemonic
	}
	if !isKnownPublic(mnemonic) {
		return errProductionMnemonic
	}
	return nil
}
