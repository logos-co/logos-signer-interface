# logos.signer/1

The contract every Logos signer module implements: `keystore_module` for keys kept in files, and
one module per hardware wallet. The signer manager, `signer_manager_module`, is its only caller for
signing. It lists every signer's accounts, prepares each request in the form the account's signer
takes, hands it over, and checks every signature before anything settles.

The IPC contract is [`signer.lidl`](../signer.lidl). A consumer declares it under
`interface_dependencies` and binds it to a module at runtime; a provider exposes the same methods
and events. Every payload is a JSON string. Field names are camelCase.

## Rules

- **Public material only.** No method returns a private key, a seed, a phrase or anything derived
  from one except a signature, and, to the manager alone, a seed's unlock key (`unlock_key`).
- **Account lists are encrypted at rest.** A signer that answers `unlock_key` keeps each seed's
  accounts encrypted under the key the manager gives it for that seed, and lists them, xpubs
  included, only while the seed is unlocked.
- **Nothing signs under the reserved purpose** `m/1280263247'`, where the unlock keys live, and an
  EVM account sits under `m/44'/60'`.
- **Signatures only.** An answer is a list of signatures, each naming the request item or PSBT input
  it belongs to. A signer never returns a signed transaction; the manager builds that from its own
  parsed copy of the request.
- **The manager checks every answer** against the account's public material, over the digest it
  computed. [`verify::check`](../src/verify.rs) is that check, and the conformance suite runs it.
- **A signer without a screen signs hashes only** (`requestKinds: ["hash"]`). The person relies on
  what the signer app shows, which the manager writes.
- **`signer_accounts`, `sign` and `unlock_key` answer the manager alone,** and a signer's
  administration answers its own app. Who may call what comes from module identity in the core.

## Methods

Every reply is `{ "ok": true, … }` or `{ "ok": false, "code": <code>, "error": <text> }`.

### `signer_info() → { ok, interface, kind, model, families, requestKinds, showsRequest, collects, unlockKey }`

| Field | Meaning |
|---|---|
| `interface` | `"logos.signer/1"` |
| `kind` | `keystore`, `keycard`, `keycard_shell`, `ledger`, `trezor`, `qr`, `mock` |
| `families` | Any of `evm`, `bitcoin` (native segwit, BIP84), `bitcoin_taproot` (key path, BIP86) |
| `requestKinds` | Any of `hash`, `evm_transaction`, `evm_message`, `evm_typed_data`, `btc_psbt` |
| `showsRequest` | The device shows the request on its own screen |
| `collects` | What the host collects before `sign`: `nothing`, `password` or `pin` |
| `unlockKey` | It answers `unlock_key` (absent: `false`) |

### `signer_accounts() → { ok, accounts: [Account] }`

```json
{ "id": "…", "family": "bitcoin", "chain": "test", "path": "m/84'/1'/0'", "fingerprint": "73c5da0a",
  "xpub": "tpub…", "key": "btc_…", "seed": "…", "label": "Savings", "available": true }
```

An EVM account carries `address`, and signs with its own key. A Bitcoin account carries its account
path, master fingerprint and `xpub`, and signs below its path. It may carry its roster `key` (`btc_`
and 32 hex of a hash over its family, chain, chain code and public key), which must match the xpub.
A signer that answers `unlock_key` names each account's `seed` the way it recognises it: a Keycard's
key UID, a Shell's master key id, a QR wallet's master fingerprint, a keystore wallet's id. A device
module keeps listing an unplugged device's accounts with `"available": false`.

`fingerprint` names the wallet an account derives from, so apps can show it beside the account. An
EVM account should carry it too whenever the signer knows the account's seed; an imported key has
none. The same account may be offered by several signers, a keystore and a hardware wallet holding
one phrase for instance: an EVM account is the same account wherever its address is, a Bitcoin one
wherever its account key is.

A signer may add `origin` to an account, for apps:

```json
"origin": { "devices": [ { "kind": "keycard", "id": "…", "name": "Work card" } ],
            "phrase": { "id": "…", "name": "Main phrase" }, "kind": "derived", "path": "m/44'/60'/0'/0/0" }
```

`devices` are the devices that hold it, `phrase` the wallet in the signer's own words, with the name
the person gave it, `kind` `derived` or `imported`. All of it is optional, and none of it is checked:
`fingerprint` is what matches a wallet across signers.

### `sign(request_json) → { ok, job }`

Starts signing and returns a job at once, because a person at a device may take minutes.

```json
{ "account": "<id>", "kind": "hash",
  "items": [ { "path": "m/84'/1'/0'/0/3", "scheme": "ecdsa", "digest": "<32 bytes hex>" } ],
  "secret": "<password or PIN, when collects asks for one>", "xpub": "<a Bitcoin account's xpub>" }
```

A Bitcoin request carries the account's `xpub`, from the wallet that has it open; the signer checks it
against the account's roster `key` and refuses another account's with `invalid`.

| Kind | Fields | Signed by |
|---|---|---|
| `hash` | `items: [{ path?, scheme, digest }]` | signers without a screen: the keystore, a bare Keycard |
| `evm_transaction` | `chainId`, `tx`: unsigned EIP-2718 bytes, hex, whose keccak-256 is the signing hash (a legacy transaction in its EIP-155 form) | devices with a screen |
| `evm_message` | `message`: the bytes `personal_sign` covers, hex | devices with a screen |
| `evm_typed_data` | `typedData`: the EIP-712 document | devices with a screen |
| `btc_psbt` | `network`, `psbt`: base64, version 0 | devices with a screen |

Schemes for `hash` items:

| Scheme | Family | Signature |
|---|---|---|
| `evm` | `evm` | recoverable ECDSA, low S; the answer carries `recoveryId` |
| `ecdsa` | `bitcoin` | ECDSA, low S, over a BIP143 sighash |
| `bip86` | `bitcoin_taproot` | BIP340 by the key tweaked as BIP86 says, with no script tree, over a BIP341 sighash |

A Bitcoin item's `path` must lie below the account's path with only unhardened levels; anything
else is refused with `invalid`. An EVM item has no `path`.

### `sign_status(job) → { ok, job, state, code?, error? }`

`state` is `working`, `confirm_on_device`, `done`, `refused` (declined on the device), `failed` or
`cancelled`. A failed job carries `code` and `error` beside its state.

### `sign_result(job) → { ok, job, signatures: [Signature] }`

```json
{ "item": 0, "signature": "<64 bytes hex>", "recoveryId": 1, "pubkey": "<33 bytes hex, or 32 x-only>" }
```

An answer to `evm_transaction`, `evm_message` or `evm_typed_data` is one signature with its
`recoveryId`. An answer to `btc_psbt` is one signature per input, and `item` is the input's index;
the signer refuses a PSBT whose inputs it would sign at a path outside the account.

Repeats until the job is swept, ten minutes after it settles. A job still running answers `busy`;
a refused or failed job answers its error.

### `cancel_sign(job) → { ok, job }`

Gives up on a live job; harmless on a settled one.

### `unlock_key(request_json) → { ok, job }`

`{ "seed": "<an account's seed>", "index": 0, "secret"? }`. The signer works out the seed's unlock
key, the compressed public key at `m/1280263247'/<index>'` ([`unlock`](../src/unlock.rs)): the
keystore from its vault, a card through `export_public`, a device by its own export or one QR round
trip. Every holder of the seed gives the same key at an index, and another index gives another: the
manager moves a seed to its next index when the key may have leaked. The manager wraps the seed's
data key under it; nothing signs at that path. **Only the signer manager may call the four
`unlock_key` methods, and no event carries their jobs.**

### `unlock_key_status(job) → { ok, job, state, code?, error? }`

As `sign_status`. A device holding another seed fails with `wrong_seed`.

### `unlock_key_result(job) → { ok, job, key }`

Once: the job forgets its answer when it is read, or a minute after it settles. `key` is 33 bytes
hex.

### `cancel_unlock_key(job) → { ok, job }`

## Events

| Event | When |
|---|---|
| `signer_accounts_changed(count)` | The accounts it offers changed, including availability |
| `signer_changed(state)` | The device connected, locked, opened the wrong app, or became busy |
| `sign_progress(job, state)` | A job moved, such as to `confirm_on_device` |

## Error codes

`locked` (needs a secret or an unlock and has neither), `wrong_secret`, `unknown_account`,
`unknown_job`, `unsupported`, `unavailable`, `busy`, `refused`, `invalid`, `internal`, `wrong_seed`
(the signer holds another seed than the one asked for).

## Conformance

Every signer module runs [`conformance::run`](../src/conformance.rs) in its own CI, in process
against its core. It checks the shape of `signer_info` and `signer_accounts`, refusals of unknown
accounts, jobs and kinds, that a wrong or missing secret signs nothing, that every account signs and
every signature checks against its public material, and that paths outside an account are refused.
For a signer that answers `unlock_key`, it also checks that every account names its seed, and that
each seed gives a 33-byte key, the same each time and read once, another at index 1, and none for a
wrong or missing secret or for a seed the signer doesn't hold. A request carrying another account's
xpub is refused.
A signer that takes whole requests gets them instead of hashes: a transaction or a message for an
EVM account and a PSBT for a Bitcoin one, the suite working out each digest itself.
[`mock::MockSigner`](../src/mock.rs) passes it with no secret, with a password, waiting for
confirmation as a device does, and taking whole requests as a device with a screen does. It can also answer wrong on purpose (`Doctor`): a signature by
another key, over another digest, or one fewer than asked, so a manager's tests can show it
refuses each. Its keys can come from another phrase, to stand beside a keystore holding the test
keys. It names its seed as a Keycard does, by the SHA-256 of its uncompressed master public key.
