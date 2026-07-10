// Copyright (C) 2019-2025, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package light

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/luxfi/crypto"
	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/go-bip32"
	"github.com/luxfi/go-bip39"
	"github.com/luxfi/ids"
)

var (
	errEmptyMnemonic      = errors.New("light: empty mnemonic")
	errProductionMnemonic = errors.New("light: refusing non-public (production) mnemonic in local-only light path")
)

// LuxCoinType is the BIP44 coin type Lux uses by canonical convention. The full
// account path is m/44'/9000'/0'/0/i (purpose 44' / coin 9000' / account 0'
// hardened; change 0 / index i non-hardened) — identical to
// genesis.LoadKeysFromMnemonic and to every canonical-BIP44 wallet (Lux Wallet,
// MetaMask, `lux key derive`), so the same seed yields the same addresses
// everywhere.
const LuxCoinType = 9000

// Account is one deterministic wallet identity derived from the light mnemonic.
// It carries only account-level material — no staker cert, no NodeID, no BLS —
// because those are intentionally non-deterministic and out of this package's
// concern.
type Account struct {
	Index        int         // BIP44 address index i
	ECPrivateKey []byte      // 32-byte secp256k1 scalar
	EVMAddress   ids.ShortID // 20-byte H160 (C-Chain / EVM)
	LuxAddress   ids.ShortID // 20-byte P/X-Chain address (secp256k1 Address)
}

// ECPrivateKeyHex returns the raw private key as lowercase hex (no 0x).
func (a Account) ECPrivateKeyHex() string { return hex.EncodeToString(a.ECPrivateKey) }

// EVMAddressHex returns the C-Chain address as 0x-prefixed hex.
func (a Account) EVMAddressHex() string { return "0x" + hex.EncodeToString(a.EVMAddress[:]) }

// LuxAddressHex returns the P/X-Chain address as 0x-prefixed hex (the raw
// 20-byte H160 form; use LuxAddress.String() for the cb58 form).
func (a Account) LuxAddressHex() string { return "0x" + a.LuxAddress.Hex() }

// accountChangeNode walks m/44'/9000'/0'/0 once so DeriveAccount / DeriveAccounts
// only pay for the final non-hardened child per index.
func accountChangeNode() (*bip32.Key, error) {
	seed := bip39.NewSeed(Mnemonic, "")
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	purpose, err := master.NewChildKey(bip32.FirstHardenedChild + 44)
	if err != nil {
		return nil, fmt.Errorf("purpose 44': %w", err)
	}
	coin, err := purpose.NewChildKey(bip32.FirstHardenedChild + LuxCoinType)
	if err != nil {
		return nil, fmt.Errorf("coin %d': %w", LuxCoinType, err)
	}
	account, err := coin.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		return nil, fmt.Errorf("account 0': %w", err)
	}
	change, err := account.NewChildKey(0)
	if err != nil {
		return nil, fmt.Errorf("change 0: %w", err)
	}
	return change, nil
}

// accountFromKey builds an Account from a 32-byte secp256k1 scalar at index i.
func accountFromKey(i int, key []byte) (Account, error) {
	secpKey, err := secp256k1.ToPrivateKey(key)
	if err != nil {
		return Account{}, fmt.Errorf("secp256k1 key %d: %w", i, err)
	}
	luxAddr := secpKey.Address() // ids.ShortID (sha256+ripemd160 of pubkey)

	ecdsaKey, err := crypto.ToECDSA(key)
	if err != nil {
		return Account{}, fmt.Errorf("ecdsa key %d: %w", i, err)
	}
	evm := crypto.PubkeyToAddress(ecdsaKey.PublicKey) // common.Address, 20 bytes
	var evmAddr ids.ShortID
	copy(evmAddr[:], evm[:])

	return Account{
		Index:        i,
		ECPrivateKey: key,
		EVMAddress:   evmAddr,
		LuxAddress:   luxAddr,
	}, nil
}

// DeriveAccount returns the deterministic wallet account at BIP44 index i
// (m/44'/9000'/0'/0/i) under the light mnemonic. Byte-for-byte identical to
// genesis.LoadKeysFromMnemonic's secp256k1 derivation and to any canonical
// BIP44 wallet on the same seed.
func DeriveAccount(i int) (Account, error) {
	if i < 0 {
		return Account{}, fmt.Errorf("light: negative account index %d", i)
	}
	change, err := accountChangeNode()
	if err != nil {
		return Account{}, err
	}
	child, err := change.NewChildKey(uint32(i)) //nolint:gosec // i >= 0 checked above
	if err != nil {
		return Account{}, fmt.Errorf("derive index %d: %w", i, err)
	}
	return accountFromKey(i, child.Key)
}

// DeriveAccounts returns the first n deterministic wallet accounts (indices
// 0..n-1). It walks the shared m/44'/9000'/0'/0 prefix once.
func DeriveAccounts(n int) ([]Account, error) {
	if n < 0 {
		return nil, fmt.Errorf("light: negative account count %d", n)
	}
	change, err := accountChangeNode()
	if err != nil {
		return nil, err
	}
	out := make([]Account, 0, n)
	for i := 0; i < n; i++ {
		child, err := change.NewChildKey(uint32(i)) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("derive index %d: %w", i, err)
		}
		acct, err := accountFromKey(i, child.Key)
		if err != nil {
			return nil, err
		}
		out = append(out, acct)
	}
	return out, nil
}
