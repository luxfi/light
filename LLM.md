# luxfi/light

Single canonical source of the well-known Lux **light** dev mnemonic and of the
deterministic **account (wallet) keys** derived from it.

## Scope
LOCAL network only — primary network ID **1337**, EVM chain ID **31337**.
The light mnemonic is public by design; it MUST NEVER back mainnet/testnet/devnet.

## What lives here (and what does NOT)
- IN: the mnemonic constant, a public-mnemonic guard, and the deterministic
  secp256k1 wallet derivation at the canonical BIP44 path `m/44'/9000'/0'/0/i`
  (EC private key + EVM/H160 address + P/X-chain address).
- OUT: staker certs, NodeIDs, BLS/PQ validator identities. Those are
  **intentionally non-deterministic** (random per-node staker keys, so a public
  seed can never impersonate a validator) and live with each node's key
  material — never derived from this mnemonic.

## API
- `Mnemonic` — the light mnemonic string (single source of truth).
- `IsLight(s) bool` — constant-time exact match.
- `RefuseOnProduction(m) error` — rejects empty + any non-public (production) seed.
- `DeriveAccount(i) (Account, error)` / `DeriveAccounts(n)` — canonical BIP44 accounts.
- `Account{ Index, ECPrivateKey, EVMAddress, LuxAddress }` + hex helpers.

Byte-for-byte identical to `genesis.LoadKeysFromMnemonic`'s secp256k1 derivation
and to any canonical BIP44 wallet on the same seed.

## Test
`go test ./...` — proves determinism across runs, guard behaviour, and a pinned
known-address vector (`i=0` EC key `b4a8…8d40`, EVM `0x5369…0a54`).
