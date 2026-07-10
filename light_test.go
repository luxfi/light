// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package light_test

import (
	"testing"

	"github.com/luxfi/light"
)

// TestDeriveAccountDeterministic proves the derivation is reproducible: two
// independent derivations of the same index yield byte-identical material.
// This is the whole point of the module — the account keys are a pure function
// of the mnemonic.
func TestDeriveAccountDeterministic(t *testing.T) {
	for i := 0; i < 5; i++ {
		a, err := light.DeriveAccount(i)
		if err != nil {
			t.Fatalf("DeriveAccount(%d) run1: %v", i, err)
		}
		b, err := light.DeriveAccount(i)
		if err != nil {
			t.Fatalf("DeriveAccount(%d) run2: %v", i, err)
		}
		if a.ECPrivateKeyHex() != b.ECPrivateKeyHex() {
			t.Fatalf("index %d: EC key not deterministic: %s != %s", i, a.ECPrivateKeyHex(), b.ECPrivateKeyHex())
		}
		if a.EVMAddress != b.EVMAddress {
			t.Fatalf("index %d: EVM addr not deterministic", i)
		}
		if a.LuxAddress != b.LuxAddress {
			t.Fatalf("index %d: Lux addr not deterministic", i)
		}
	}
}

// TestDeriveAccountsMatchesSingle proves the batched walk agrees with the
// single-index walk (shared-prefix optimisation is correct).
func TestDeriveAccountsMatchesSingle(t *testing.T) {
	batch, err := light.DeriveAccounts(5)
	if err != nil {
		t.Fatalf("DeriveAccounts: %v", err)
	}
	for i, a := range batch {
		single, err := light.DeriveAccount(i)
		if err != nil {
			t.Fatalf("DeriveAccount(%d): %v", i, err)
		}
		if a.ECPrivateKeyHex() != single.ECPrivateKeyHex() ||
			a.EVMAddress != single.EVMAddress || a.LuxAddress != single.LuxAddress {
			t.Fatalf("index %d: batch != single", i)
		}
	}
}

// TestKnownVector pins the canonical BIP44 m/44'/9000'/0'/0/0 derivation under
// the light mnemonic. The EC private key is the value independently verified
// against the genesis derivation path (bip39/bip32 + m/44'/9000'); the
// addresses are pinned so a future dependency bump that silently changes the
// derivation fails loudly here.
func TestKnownVector(t *testing.T) {
	const (
		wantEC  = "b4a85564ce281c3259c23cc37c04fd79b4206a6783ca2ee6aa0fbc2ce7838d40"
		wantEVM = "0x5369615110ca435bdf798f31c20ba6163d7b0a54"
		wantLux = "0x925a8d81bce1386904b007a020bce60927d61cf0"
	)
	a, err := light.DeriveAccount(0)
	if err != nil {
		t.Fatalf("DeriveAccount(0): %v", err)
	}
	if a.ECPrivateKeyHex() != wantEC {
		t.Fatalf("index 0 EC key: got %s want %s", a.ECPrivateKeyHex(), wantEC)
	}
	t.Logf("PIN index0 EVM=%s Lux=%s (cb58=%s)", a.EVMAddressHex(), a.LuxAddressHex(), a.LuxAddress.String())
	if wantEVM != "0x__PIN_ME__" && a.EVMAddressHex() != wantEVM {
		t.Fatalf("index 0 EVM: got %s want %s", a.EVMAddressHex(), wantEVM)
	}
	if wantLux != "0x__PIN_ME__" && a.LuxAddressHex() != wantLux {
		t.Fatalf("index 0 Lux: got %s want %s", a.LuxAddressHex(), wantLux)
	}
}

// TestIsLight pins exact, constant-time membership.
func TestIsLight(t *testing.T) {
	if !light.IsLight(light.Mnemonic) {
		t.Fatal("IsLight must accept the light mnemonic")
	}
	if light.IsLight("") {
		t.Fatal("IsLight must reject empty")
	}
	if light.IsLight("light light light light light light light light light light light light") {
		t.Fatal("IsLight must reject a near-miss mnemonic")
	}
}

// TestRefuseOnProduction proves the guard rejects empty and a production
// (non-public) mnemonic, and admits recognised public/dev seeds.
func TestRefuseOnProduction(t *testing.T) {
	if err := light.RefuseOnProduction(""); err == nil {
		t.Fatal("empty mnemonic must be refused")
	}
	// A plausible real/production seed (valid-looking words, not in any public
	// list) must be refused from the local-only light path.
	prod := "vessel ladder alter error federal sibling chat ability sun glass valve picture"
	if err := light.RefuseOnProduction(prod); err == nil {
		t.Fatal("production mnemonic must be refused")
	}
	if err := light.RefuseOnProduction(light.Mnemonic); err != nil {
		t.Fatalf("light mnemonic must be admitted: %v", err)
	}
	// Other well-known public dev seeds are admitted too (parity with genesis).
	for _, m := range []string{
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"test test test test test test test test test test test junk",
	} {
		if err := light.RefuseOnProduction(m); err != nil {
			t.Fatalf("public dev seed %q must be admitted: %v", m, err)
		}
	}
}
