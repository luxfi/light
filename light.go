// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

// Package light is the single canonical source of the well-known Lux "light"
// dev mnemonic and of the deterministic ACCOUNT (wallet) keys derived from it.
//
// Scope: LOCAL network only (primary network ID 1337, EVM chain ID 31337).
// The mnemonic is public by design — anyone can derive every account key from
// it, so it MUST NEVER back a production network. RefuseOnProduction is the
// guard that enforces this.
//
// This package deliberately owns ONLY the deterministic value: the mnemonic
// and the secp256k1 wallet keys / addresses at the canonical BIP44 path
// m/44'/9000'/0'/0/i. It has NO staker-cert / NodeID / BLS surface: validator
// staking identities are intentionally NON-deterministic (random per-node
// staker keys, so a public seed can never impersonate a node) and live with
// each node's key material, never here.
package light

import "crypto/subtle"

// Mnemonic is the well-known public Lux dev seed. Pass it as the value of
// LUX_MNEMONIC (or LIGHT_MNEMONIC) to bootstrap a local network. It is the
// SINGLE source of truth for this string across the ecosystem — every other
// package that needs it should reference light.Mnemonic, never re-declare it.
const Mnemonic = "light light light light light light light light light light light energy"

// knownPublicMnemonics is the curated set of seeds anyone in the world can
// derive from. RefuseOnProduction accepts exactly these (they are safe to use
// on a throwaway local mesh); anything else is treated as a real/production
// seed that must never flow through the light (local-only) derivation path.
//
// Ported verbatim from genesis' light_mnemonic_guard so the two guards agree.
var knownPublicMnemonics = []string{
	Mnemonic,
	// BIP-39 test vector #1 (canonical "abandon" mnemonic).
	"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
	// BIP-39 test vector #5.
	"legal winner thank year wave sausage worth useful legal winner thank yellow",
	// Hardhat / Foundry default test mnemonic.
	"test test test test test test test test test test test junk",
	// Trezor demo seed.
	"witch collapse practice feed shame open despair creek road again ice least",
	// Common "all abandon" BIP-39 vector.
	"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
}

// IsLight reports whether s is exactly the light Mnemonic. Compared in constant
// time so a timing attacker cannot probe the running config from outside.
func IsLight(s string) bool {
	return subtle.ConstantTimeCompare([]byte(s), []byte(Mnemonic)) == 1
}

// isKnownPublic reports whether m appears in any well-known public list. Every
// entry is compared (no short-circuit) so the loop reveals neither which entry
// matched nor whether it matched early.
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

// RefuseOnProduction returns a non-nil error when the supplied mnemonic must
// not be used through the light (local-only) derivation path:
//
//   - empty string        → error (no mnemonic set)
//   - any non-public seed  → error (looks like a real/production mnemonic;
//     luxfi/light is for local dev only, and a production seed must never be
//     fed into a code path that derives from a publicly-known layout)
//
// A recognised public/dev mnemonic (light, BIP-39 vectors, Hardhat, Trezor…)
// returns nil. This mirrors genesis.RefuseLightMnemonicOnProduction, minus the
// network-ID coupling: the caller decides WHERE it runs; this decides WHETHER a
// mnemonic is a safe public/dev value.
func RefuseOnProduction(mnemonic string) error {
	if mnemonic == "" {
		return errEmptyMnemonic
	}
	if !isKnownPublic(mnemonic) {
		return errProductionMnemonic
	}
	return nil
}
