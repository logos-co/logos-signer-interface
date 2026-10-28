# logos-signer-interface

`logos.signer/1`, the contract every Logos signer module implements so the signer manager can list
its accounts and have it sign: `keystore_module` for keys kept in files, and one module per hardware
wallet.

- [`signer.lidl`](signer.lidl): the IPC contract. A consumer lists it under `interface_dependencies`
  and binds it to a signer module at runtime.
- [`docs/interface.md`](docs/interface.md): the JSON every method takes and returns, the rules and
  the error codes.
- [`wallets.lidl`](wallets.lidl) and [`docs/wallets.md`](docs/wallets.md): `logos.wallets/1`, what the
  signer manager offers every module about wallets. A module binds it to `signer_manager_module` at
  runtime to get its own keys for a wallet's data, and a signer registers the seeds it adds.
- The Rust crate `logos-signer-interface`:
  - `wire`: the payload types.
  - `verify`: checks a signature against an account's address or xpub.
  - `unlock`: a seed's unlock key path and checks, the roster key, and the path guards.
  - `wallets`: `logos.wallets/1`'s payloads, and the box a module keeps a wallet's data in.
  - `jobs`: job bookkeeping a signer module can reuse.
  - `json`: builds a module's replies from a `Signer` and reads them back.
  - `conformance` (feature): the suite every signer runs in its own CI.
  - `mock` (feature): a software signer for tests. It can wait for a device's confirmation, answer wrong on purpose, or take whole requests as a device with a screen does: EVM transactions and messages, and PSBTs, whose digests it works out itself.
  - `psbt` (feature): for signers that hand a device the whole PSBT, over USB or QR codes. It checks that every input is the account's, names each taproot input's internal key as devices want it, and collects the signatures the device added.

```toml
logos-signer-interface = { git = "https://github.com/logos-co/logos-signer-interface", rev = "…" }
```

```sh
cargo test --all-features
```

Licensed under MIT or Apache-2.0.
