# logos.wallets/1

What the signer manager, `signer_manager_module`, offers every module about wallets. A **wallet**
is a seed, whichever signers hold it. The person unlocks it once per session in the Signer app, and
every module then keeps its data about that wallet encrypted with keys of its own, which the
manager derives from the seed's key.

The IPC contract is [`wallets.lidl`](../wallets.lidl). A module declares it under
`interface_dependencies` and binds it to `signer_manager_module` at runtime, so it needs no
build-time dependency on the manager, which itself depends on several signers. Every payload is a
JSON string. Field names are camelCase.

## Methods

### `wallets() → { ok, wallets: [{ seed, name, locked, kinds, privateName? }] }`

Every wallet. `name` shows while it is locked; `privateName`, when the person gave one, once it is
unlocked. Any named module.

### `data_key(params_json) → { ok, key, generation }`

`{ "seed": "<a wallet's seed, or \"profile\">", "scope": "<what the key is for>", "generation"? }`.
The key, 32 bytes as hex, that the calling module keeps that scope of that wallet's data under:
`HKDF-SHA256(seed key, "logos/data/v1", module ‖ 0 ‖ scope ‖ 0 ‖ generation)`. The manager names
the module by its caller identity, so a module only ever gets keys of its own.
- A signer may name the seed the way it does, its own recogniser for it (a Keycard's key UID, a
  Shell's master key id), when it is one of that seed's holders.
- A module that knows an account and not its seed asks `{ "account": "<id or address>", "scope",
  "generation"? }` instead, and the answer also names the `seed`. The manager looks the account up
  among the accounts its signers last listed; one it doesn't know answers `code: unavailable`.
- A locked wallet answers `code: locked`.
- The current generation is the default. An earlier one still answers, so a module reads data
  sealed before the person changed the wallet's keys, and seals it again under the current key.
- `"profile"` is a key for data of no wallet, such as contacts: any unlocked wallet opens it.

### `enroll_seed(params_json) → { ok, seed, new, unlocked }`

A signer registers a seed it just added, from its add flow, while the holder's unlock key is at
hand, so adding never asks twice: `{ "seed": "<the signer's own name for it>", "kind",
"unlockKey"?, "name", "origin"?, "birthday"? }`.
- `unlockKey` is the compressed public key at `m/1280263247'/0'` ([`unlock`](../src/unlock.rs)),
  33 bytes as hex; a holder that can't give one leaves it out.
- The answer names the manager's wallet for that seed: a new one, unlocked, or a known one that
  gained this holder.

Only the manager's configured signers may call it.

## Events

| Event | When |
|---|---|
| `wallets_changed(seed)` | A wallet was added, unlocked or changed: read `wallets` again, and ask `data_key` again |
| `wallets_locked(count)` | Wallets were locked: drop what was read under their keys |

## The box

[`wallets::seal`](../src/wallets.rs) keeps a module's data under a key from `data_key` as `{ "v":
1, "generation": g, "box": hex(nonce ‖ ciphertext) }`, XChaCha20-Poly1305. The associated data
names what it is, a file's name for instance, so one box can't stand in for another.
[`wallets::generation`](../src/wallets.rs) says which generation to ask for before
[`wallets::open`](../src/wallets.rs) opens it.

[`sealed::SealedDocs`](../src/sealed.rs) keeps one such box per seed in one file, `{ "v": 1,
"seeds": { "<seed>": <box> } }` at 0600: a signer's account lists, for instance. A seed's document
opens once its key arrives (`wanted` says which generation to ask for) and is sealed again under the
current generation. While the seed is locked, its document is not read and can't be overwritten.
A document written before its seed's key is known, such as the accounts of a seed just added,
waits in memory until the key comes.

A module calling `data_key` from inside a call the manager made to it would wait on itself. A signer
asks for its keys when `wallets_changed` says a wallet unlocked, never while answering
`signer_accounts`.
