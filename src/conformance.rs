//! The suite every signer module runs in its own CI. It drives a [`Signer`] in process and checks
//! every answer with [`crate::verify`], against the account's public material only. A signer that
//! takes whole requests gets them: a transaction or a message for an EVM account, a PSBT for a
//! Bitcoin one, each digest worked out here.
//!
//! ```ignore
//! let fixture = Fixture { secret: Some(Secret::new("pw")), wrong_secret: Some(Secret::new("no")) };
//! conformance::run(&mut my_signer, &fixture, &mut |_, _| {});
//! ```

use std::str::FromStr;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::{OsRng, RngCore};
use sha3::{Digest, Keccak256};

use crate::unlock::{check_unlock_key, check_xpub, evm_path_ok, is_reserved};
use crate::verify::{check, derive};
use crate::wire::*;
use crate::{Signer, INTERFACE};

pub struct Fixture {
    /// The secret `sign` needs, when `signer_info` says it collects one.
    pub secret: Option<Secret>,
    pub wrong_secret: Option<Secret>,
}

/// Called while a job waits on its device: confirm it the way a person would.
pub type Drive<'a, S> = dyn FnMut(&mut S, &str) + 'a;

fn random_digest() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Hash items for an account: two for Bitcoin (a receive and a change key), one for EVM.
pub fn items_for(account: &Account) -> Vec<HashItem> {
    match account.family {
        Family::Evm => vec![HashItem {
            path: None,
            scheme: Scheme::Evm,
            digest: random_digest(),
        }],
        family => {
            let scheme = if family == Family::Bitcoin {
                Scheme::Ecdsa
            } else {
                Scheme::Bip86
            };
            let base = account.path.clone().unwrap_or_default();
            ["0/0", "1/3"]
                .into_iter()
                .map(|tail| HashItem {
                    path: Some(format!("{base}/{tail}")),
                    scheme,
                    digest: random_digest(),
                })
                .collect()
        }
    }
}

fn request(account: &Account, items: Vec<HashItem>, secret: Option<Secret>) -> SignRequest {
    SignRequest {
        account: account.id.clone(),
        payload: Payload::Hash { items },
        secret,
        xpub: account.xpub.clone(),
    }
}

/// Run an unlock-key job to its end, driving the device while it waits.
fn settle_key<S: Signer>(s: &mut S, job: &str, drive: &mut Drive<'_, S>) -> JobStatus {
    for _ in 0..50 {
        let st = s
            .unlock_key_status(job)
            .expect("status of an unlock-key job the signer just started");
        if st.state.is_final() {
            return st;
        }
        drive(s, job);
    }
    panic!("an unlock-key job never settled");
}

/// A seed's unlock key at `index`, as the manager gets it, or why the signer gave none.
pub fn unlock_key_of<S: Signer>(
    s: &mut S,
    seed: &str,
    index: u32,
    secret: Option<Secret>,
    drive: &mut Drive<'_, S>,
) -> Result<UnlockKey> {
    let job = s.unlock_key(UnlockKeyRequest {
        seed: seed.into(),
        index,
        secret,
    })?;
    let st = settle_key(s, &job, drive);
    if st.state != JobState::Done {
        return Err(st.error.expect("a failed job says why"));
    }
    s.unlock_key_result(&job)
}

/// A request in a kind the signer takes, and the items its answer must sign.
pub fn request_for(info: &SignerInfo, account: &Account, secret: Option<Secret>) -> (SignRequest, Vec<HashItem>) {
    let takes = |k| info.request_kinds.contains(&k);
    let (payload, items) = if takes(RequestKind::Hash) {
        let items = items_for(account);
        (Payload::Hash { items: items.clone() }, items)
    } else if account.family == Family::Evm && takes(RequestKind::EvmTransaction) {
        let tx = eip1559(OsRng.next_u32().into());
        let item = evm_item(&tx);
        (
            Payload::EvmTransaction {
                chain_id: 1,
                tx: hex::encode(tx),
            },
            vec![item],
        )
    } else if account.family == Family::Evm && takes(RequestKind::EvmMessage) {
        let text = format!("conformance {}", random_digest());
        let item = evm_item(format!("\x19Ethereum Signed Message:\n{}{text}", text.len()).as_bytes());
        (
            Payload::EvmMessage {
                message: hex::encode(text),
            },
            vec![item],
        )
    } else if account.family.is_bitcoin() && takes(RequestKind::BtcPsbt) {
        let base = account.path.clone().unwrap_or_default();
        let paths: Vec<(String, String)> = ["0/0", "1/3"]
            .into_iter()
            .map(|tail| (format!("{base}/{tail}"), format!("{base}/{tail}")))
            .collect();
        let (psbt, items) = psbt_for(account, &paths);
        let network = if account.chain == Some(Chain::Main) {
            "bitcoin"
        } else {
            "testnet"
        };
        (
            Payload::BtcPsbt {
                network: network.into(),
                psbt,
            },
            items,
        )
    } else {
        panic!(
            "{}: no request kind the suite can build for a {:?} account",
            account.id, account.family
        );
    };
    (
        SignRequest {
            account: account.id.clone(),
            payload,
            secret,
            xpub: account.xpub.clone(),
        },
        items,
    )
}

fn evm_item(data: &[u8]) -> HashItem {
    HashItem {
        path: None,
        scheme: Scheme::Evm,
        digest: hex::encode(Keccak256::digest(data)),
    }
}

/// An unsigned EIP-1559 transfer on chain 1: the bytes whose keccak-256 is its signing hash.
pub fn eip1559(nonce: u64) -> Vec<u8> {
    let to = [0xdd; 20];
    let fields = [
        rlp_uint(1),
        rlp_uint(nonce),
        rlp_uint(1_000_000_000),
        rlp_uint(30_000_000_000),
        rlp_uint(21_000),
        rlp_bytes(&to),
        rlp_uint(1_000_000_000_000_000),
        rlp_bytes(&[]),
        rlp_list(&[]),
    ];
    let mut tx = vec![0x02];
    tx.extend(rlp_list(&fields));
    tx
}

fn rlp_len(offset: u8, len: usize) -> Vec<u8> {
    if len < 56 {
        return vec![offset + len as u8];
    }
    let be: Vec<u8> = len.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
    let mut out = vec![offset + 55 + be.len() as u8];
    out.extend(be);
    out
}

fn rlp_bytes(b: &[u8]) -> Vec<u8> {
    if b.len() == 1 && b[0] < 0x80 {
        return b.to_vec();
    }
    let mut out = rlp_len(0x80, b.len());
    out.extend_from_slice(b);
    out
}

fn rlp_uint(n: u64) -> Vec<u8> {
    let be: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
    rlp_bytes(&be)
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload = items.concat();
    let mut out = rlp_len(0xc0, payload.len());
    out.extend(payload);
    out
}

/// A PSBT with one input per `(key path, origin path)`: it spends the account's key at the first
/// path and names the second as its origin. Returns it in base64, with one item per input.
pub fn psbt_for(account: &Account, inputs: &[(String, String)]) -> (String, Vec<HashItem>) {
    use bitcoin::bip32::{DerivationPath, Fingerprint};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
    use bitcoin::{
        absolute, transaction, Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };

    let secp = Secp256k1::verification_only();
    let (xpub, base) = (
        account.xpub.as_deref().unwrap_or_default(),
        account.path.as_deref().unwrap_or_default(),
    );
    let fingerprint = Fingerprint::from_str(account.fingerprint.as_deref().unwrap_or_default()).expect("fingerprint");
    let mut prevouts = Vec::new();
    let mut keys = Vec::new();
    for (key_path, _) in inputs {
        let k = derive(xpub, base, key_path).expect("a key below the account");
        let key = PublicKey::from_slice(k.to_encoded_point(true).as_bytes()).expect("key");
        let script_pubkey = match account.family {
            Family::Bitcoin => ScriptBuf::new_p2wpkh(&CompressedPublicKey(key).wpubkey_hash()),
            _ => ScriptBuf::new_p2tr(&secp, key.x_only_public_key().0, None),
        };
        prevouts.push(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey,
        });
        keys.push(key);
    }
    // Each coin comes from a transaction of its own, which a native segwit input carries whole, as
    // wallets send it: a device such as a Ledger warns about an input without it.
    let mut salt = [0u8; 4];
    OsRng.fill_bytes(&mut salt);
    let funding: Vec<Transaction> = prevouts
        .iter()
        .enumerate()
        .map(|(i, prev)| Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::from_consensus(u32::from_be_bytes(salt) % 400_000_000 + i as u32),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![prev.clone()],
        })
        .collect();
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: funding
            .iter()
            .map(|f| TxIn {
                previous_output: OutPoint::new(f.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(40_000 * inputs.len() as u64),
            script_pubkey: prevouts[0].script_pubkey.clone(),
        }],
    };
    let mut psbt = bitcoin::Psbt::from_unsigned_tx(tx).expect("an unsigned transaction");
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let mut items = Vec::new();
    for (i, ((key_path, origin), key)) in inputs.iter().zip(&keys).enumerate() {
        let source = (fingerprint, DerivationPath::from_str(origin).expect("origin path"));
        psbt.inputs[i].witness_utxo = Some(prevouts[i].clone());
        if account.family == Family::Bitcoin {
            psbt.inputs[i].non_witness_utxo = Some(funding[i].clone());
        }
        let (scheme, digest) = if account.family == Family::Bitcoin {
            psbt.inputs[i].bip32_derivation.insert(*key, source);
            let prev = &prevouts[i];
            let h = cache
                .p2wpkh_signature_hash(i, &prev.script_pubkey, prev.value, EcdsaSighashType::All)
                .expect("sighash");
            (Scheme::Ecdsa, h.to_byte_array())
        } else {
            // A key-path spend names its internal key, as wallets write it; the Keycard Shell requires it.
            psbt.inputs[i].tap_internal_key = Some(key.x_only_public_key().0);
            psbt.inputs[i]
                .tap_key_origins
                .insert(key.x_only_public_key().0, (vec![], source));
            let h = cache
                .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default)
                .expect("sighash");
            (Scheme::Bip86, h.to_byte_array())
        };
        items.push(HashItem {
            path: Some(key_path.clone()),
            scheme,
            digest: hex::encode(digest),
        });
    }
    (psbt.to_string(), items)
}

/// Run a job to its end, driving the device while it waits.
fn settle<S: Signer>(s: &mut S, job: &str, drive: &mut Drive<'_, S>) -> JobStatus {
    for _ in 0..50 {
        let st = s.status(job).expect("status of a job the signer just started");
        if st.state.is_final() {
            return st;
        }
        drive(s, job);
    }
    panic!("a job never settled");
}

pub fn info_is_well_formed<S: Signer>(s: &S) {
    let info = s.info();
    assert_eq!(info.interface, INTERFACE, "interface version");
    assert!(!info.kind.is_empty(), "kind");
    assert!(!info.families.is_empty(), "families");
    assert!(!info.request_kinds.is_empty(), "request kinds");
    if !info.shows_request {
        assert!(
            info.request_kinds == [RequestKind::Hash],
            "a signer without a screen signs hashes only"
        );
    }
}

pub fn accounts_are_public_and_match_info<S: Signer>(s: &mut S) {
    let info = s.info();
    let accounts = s.accounts().expect("accounts");
    for a in &accounts {
        assert!(!a.id.is_empty(), "account id");
        assert!(
            info.families.contains(&a.family),
            "{}: family {:?} not in signer_info",
            a.id,
            a.family
        );
        // Optional for EVM, required for Bitcoin below: when there, 8 hex digits.
        if let Some(fp) = a.fingerprint.as_deref() {
            assert!(
                fp.len() == 8 && fp.bytes().all(|b| b.is_ascii_hexdigit()),
                "{}: fingerprint {fp:?}, 8 hex digits",
                a.id
            );
        }
        match a.family {
            Family::Evm => {
                let addr = a.address.as_deref().unwrap_or_default();
                assert!(
                    addr.starts_with("0x") && addr.len() == 42,
                    "{}: EVM address {addr:?}",
                    a.id
                );
            }
            _ => {
                let xpub = a
                    .xpub
                    .as_deref()
                    .unwrap_or_else(|| panic!("{}: a Bitcoin account lists its xpub", a.id));
                assert!(
                    xpub.starts_with("xpub") || xpub.starts_with("tpub"),
                    "{}: an xpub, never a private key",
                    a.id
                );
                if let Some(key) = a.key.as_deref() {
                    assert!(
                        key.starts_with("btc_") && key.len() == 36,
                        "{}: roster key {key:?}",
                        a.id
                    );
                    check_xpub(key, a.family, a.chain, xpub).unwrap_or_else(|e| panic!("{}: {e}", a.id));
                }
                assert!(a.path.is_some() && a.chain.is_some(), "{}: path and chain", a.id);
                assert_eq!(a.fingerprint.as_deref().map(str::len), Some(8), "{}: fingerprint", a.id);
            }
        }
        if info.unlock_key {
            assert!(
                a.seed.as_deref().is_some_and(|s| !s.is_empty()),
                "{}: a signer that answers unlock_key names each account's seed",
                a.id
            );
        }
        if let Some(path) = a.path.as_deref() {
            assert!(!is_reserved(path), "{}: an account under the reserved purpose", a.id);
            if a.family == Family::Evm {
                assert!(evm_path_ok(path), "{}: an EVM account under m/44'/60'", a.id);
            }
        }
    }
}

/// Each seed gives one unlock key per index, the same every time and read once; another index
/// gives another key. A wrong secret or another seed's name gets none.
pub fn unlock_keys_work<S: Signer>(s: &mut S, fx: &Fixture, drive: &mut Drive<'_, S>) {
    let info = s.info();
    if !info.unlock_key {
        return;
    }
    let mut seeds: Vec<String> = s
        .accounts()
        .expect("accounts")
        .into_iter()
        .filter_map(|a| a.seed)
        .collect();
    seeds.sort();
    seeds.dedup();
    let mut seen = Vec::new();
    for seed in &seeds {
        let first = unlock_key_of(s, seed, 0, fx.secret.clone(), drive).unwrap_or_else(|e| panic!("{seed}: {e}"));
        check_unlock_key(first.key.expose()).unwrap_or_else(|e| panic!("{seed}: {e}"));
        let again = unlock_key_of(s, seed, 0, fx.secret.clone(), drive).unwrap_or_else(|e| panic!("{seed}: {e}"));
        assert_eq!(again.key, first.key, "{seed}: the same key every time");
        let next = unlock_key_of(s, seed, 1, fx.secret.clone(), drive).unwrap_or_else(|e| panic!("{seed}: {e}"));
        assert_ne!(next.key, first.key, "{seed}: index 1 gives another key");
        assert!(!seen.contains(&first.key), "{seed}: another seed's unlock key");
        seen.push(first.key);

        let job = s
            .unlock_key(UnlockKeyRequest {
                seed: seed.clone(),
                index: 0,
                secret: fx.secret.clone(),
            })
            .expect("unlock_key");
        settle_key(s, &job, drive);
        s.unlock_key_result(&job).expect("read once");
        assert!(s.unlock_key_result(&job).is_err(), "{seed}: an unlock key read twice");

        if info.collects != Collects::Nothing {
            for (secret, code) in [
                (fx.wrong_secret.clone(), ErrorCode::WrongSecret),
                (None, ErrorCode::Locked),
            ] {
                let e = unlock_key_of(s, seed, 0, secret, drive).expect_err("an unlock key without its secret");
                assert_eq!(e.code, code, "{seed}");
            }
        }
    }
    let foreign = unlock_key_of(s, &"0".repeat(64), 0, fx.secret.clone(), drive)
        .expect_err("an unlock key for a seed it doesn't hold");
    assert!(
        matches!(foreign.code, ErrorCode::WrongSeed | ErrorCode::UnknownAccount),
        "another seed: {:?}",
        foreign.code
    );
}

/// A Bitcoin request carrying another account's xpub is refused.
pub fn a_foreign_xpub_is_refused<S: Signer>(s: &mut S, fx: &Fixture, drive: &mut Drive<'_, S>) {
    let info = s.info();
    let bitcoin: Vec<Account> = s
        .accounts()
        .expect("accounts")
        .into_iter()
        .filter(|a| a.family.is_bitcoin() && a.key.is_some())
        .collect();
    let [one, two, ..] = &bitcoin[..] else {
        return;
    };
    let (mut r, _) = request_for(&info, one, fx.secret.clone());
    r.xpub = two.xpub.clone();
    let refused = match s.sign(r) {
        Err(e) => e,
        Ok(job) => settle(s, &job, drive)
            .error
            .expect("signed with another account's xpub"),
    };
    assert_eq!(refused.code, ErrorCode::Invalid, "{}", one.id);
}

pub fn unknown_accounts_and_jobs_are_refused<S: Signer>(s: &mut S, fx: &Fixture) {
    let ghost = Account {
        id: "no-such-account".into(),
        family: Family::Evm,
        chain: None,
        path: None,
        fingerprint: None,
        address: None,
        xpub: None,
        key: None,
        seed: None,
        label: None,
        available: true,
    };
    let info = s.info();
    let real = s.accounts().expect("accounts");
    let mut r = match real.first() {
        Some(a) => request_for(&info, a, fx.secret.clone()).0,
        None => request(&ghost, items_for(&ghost), fx.secret.clone()),
    };
    r.account = ghost.id.clone();
    let e = s.sign(r).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnknownAccount);
    assert_eq!(s.status("job_unknown").unwrap_err().code, ErrorCode::UnknownJob);
    assert_eq!(s.result("job_unknown").unwrap_err().code, ErrorCode::UnknownJob);
}

pub fn kinds_it_does_not_sign_are_refused<S: Signer>(s: &mut S, fx: &Fixture) {
    let info = s.info();
    let Some(account) = s
        .accounts()
        .expect("accounts")
        .into_iter()
        .find(|a| a.family == Family::Evm)
    else {
        return;
    };
    if !info.request_kinds.contains(&RequestKind::EvmMessage) {
        let r = SignRequest {
            account: account.id.clone(),
            payload: Payload::EvmMessage {
                message: hex::encode("hello"),
            },
            secret: fx.secret.clone(),
            xpub: None,
        };
        assert_eq!(s.sign(r).unwrap_err().code, ErrorCode::Unsupported);
    }
    if !info.request_kinds.contains(&RequestKind::Hash) {
        let r = request(&account, items_for(&account), fx.secret.clone());
        assert_eq!(
            s.sign(r).unwrap_err().code,
            ErrorCode::Unsupported,
            "a device that shows requests signs no bare hash"
        );
    }
}

pub fn a_wrong_or_missing_secret_signs_nothing<S: Signer>(s: &mut S, fx: &Fixture, drive: &mut Drive<'_, S>) {
    if s.info().collects == Collects::Nothing {
        return;
    }
    let info = s.info();
    let account = s.accounts().expect("accounts").remove(0);
    for (secret, code) in [
        (fx.wrong_secret.clone(), ErrorCode::WrongSecret),
        (None, ErrorCode::Locked),
    ] {
        let refused = match s.sign(request_for(&info, &account, secret).0) {
            Err(e) => e,
            Ok(job) => {
                let st = settle(s, &job, drive);
                assert_ne!(st.state, JobState::Done, "signed without its secret");
                st.error.expect("a failed job says why")
            }
        };
        assert_eq!(refused.code, code);
    }
}

pub fn every_account_signs_and_every_signature_checks<S: Signer>(s: &mut S, fx: &Fixture, drive: &mut Drive<'_, S>) {
    let info = s.info();
    for account in s.accounts().expect("accounts") {
        let (r, items) = request_for(&info, &account, fx.secret.clone());
        let job = s.sign(r).expect("sign");
        let st = settle(s, &job, drive);
        assert_eq!(st.state, JobState::Done, "{}: {:?}", account.id, st.error);
        let sigs = s.result(&job).expect("result");
        assert_eq!(sigs.len(), items.len(), "{}: one signature per item", account.id);
        for sig in &sigs {
            check(&account, &items[sig.item], sig).unwrap_or_else(|e| panic!("{}: {e}", account.id));
        }
        assert_eq!(s.result(&job).expect("result again"), sigs, "results repeat");
        s.cancel(&job).expect("cancelling a finished job is harmless");
        assert_eq!(s.status(&job).expect("status").state, JobState::Done);
    }
}

pub fn paths_outside_an_account_are_refused<S: Signer>(s: &mut S, fx: &Fixture, drive: &mut Drive<'_, S>) {
    for account in s
        .accounts()
        .expect("accounts")
        .into_iter()
        .filter(|a| a.family.is_bitcoin())
    {
        let outside = "m/84'/1'/99'/0/0".to_string();
        let r = if s.info().request_kinds.contains(&RequestKind::Hash) {
            let mut items = items_for(&account);
            items[0].path = Some(outside);
            request(&account, items, fx.secret.clone())
        } else {
            let base = account.path.clone().unwrap_or_default();
            let (psbt, _) = psbt_for(&account, &[(format!("{base}/0/0"), outside)]);
            SignRequest {
                account: account.id.clone(),
                payload: Payload::BtcPsbt {
                    network: "testnet".into(),
                    psbt,
                },
                secret: fx.secret.clone(),
                xpub: account.xpub.clone(),
            }
        };
        let refused = match s.sign(r) {
            Err(e) => e,
            Ok(job) => settle(s, &job, drive).error.expect("signed outside the account"),
        };
        assert_eq!(refused.code, ErrorCode::Invalid, "{}", account.id);
    }
}

/// Every check, in order.
pub fn run<S: Signer>(s: &mut S, fx: &Fixture, drive: &mut Drive<'_, S>) {
    info_is_well_formed(s);
    accounts_are_public_and_match_info(s);
    unknown_accounts_and_jobs_are_refused(s, fx);
    kinds_it_does_not_sign_are_refused(s, fx);
    a_wrong_or_missing_secret_signs_nothing(s, fx, drive);
    every_account_signs_and_every_signature_checks(s, fx, drive);
    paths_outside_an_account_are_refused(s, fx, drive);
    unlock_keys_work(s, fx, drive);
    a_foreign_xpub_is_refused(s, fx, drive);
}
