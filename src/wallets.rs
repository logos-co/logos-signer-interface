//! What the signer manager offers every module about wallets, bound at runtime through
//! `wallets.lidl` so no module depends on the manager at build time: the wallets there are, a
//! module's own key for a wallet's data, and, for signers, registering a seed they add, naming it
//! and forgetting it. Also the box every module keeps that data in. See `docs/wallets.md`.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::wire::{parse_reply, ErrorCode, Result, Secret, SignerError};

/// `data_key`'s name for the key any unlocked wallet opens, for data of no wallet in particular.
pub const PROFILE: &str = "profile";
const BOX_VERSION: u32 = 1;

fn invalid(msg: impl Into<String>) -> SignerError {
    SignerError::new(ErrorCode::Invalid, msg)
}

/// A module's key for one scope of a wallet's data: `{ seed, scope, generation? }`. The manager
/// names the module by its caller identity; the current generation is the default.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DataKeyRequest {
    pub seed: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u32>,
}

/// The same key, for the wallet that holds an account: `{ account, scope, generation? }`, for a
/// module that knows its accounts by address or id and not by seed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountKeyRequest {
    pub account: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u32>,
}

/// The key, 32 bytes as hex, and its generation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DataKey {
    pub key: Secret,
    pub generation: u32,
}

/// A key asked for by account, with the wallet it belongs to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountKey {
    pub seed: String,
    #[serde(flatten)]
    pub key: DataKey,
}

/// What a signer registers from its add flow, while the holder's unlock key is at hand.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnrollSeed {
    /// The seed as this signer names it ([`crate::Account::seed`]).
    pub seed: String,
    /// The signer's kind: `keystore`, `keycard`, `keycard_shell`, `qr`.
    pub kind: String,
    /// The unlock key at index 0, 33 bytes as hex; none from a holder that can't give one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlock_key: Option<Secret>,
    /// The name the person gave it, shown while it is locked.
    pub name: String,
}

/// The manager's wallet for that seed: new or known, and whether it is unlocked now.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Enrolled {
    pub seed: String,
    pub new: bool,
    pub unlocked: bool,
}

/// A wallet, as `wallets()` lists it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Wallet {
    pub seed: String,
    pub name: String,
    pub locked: bool,
    #[serde(default)]
    pub kinds: Vec<String>,
    /// Shown once unlocked, when the person gave one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_name: Option<String>,
    /// The person gave `name`, so every holder shows it.
    #[serde(default)]
    pub named: bool,
    /// To a holder of it only: the seed as that holder names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_seed: Option<String>,
}

/// A holder's app renamed a wallet: `name_seed`'s params.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NameSeed {
    /// The seed as this signer names it.
    pub seed: String,
    pub name: String,
}

/// A holder removed a wallet in its own app: `forget_seed`'s params.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ForgetSeed {
    /// The seed as this signer names it.
    pub seed: String,
}

/// `forget_seed`'s answer: the manager's seed, and whether its wallet went with this holder, the last.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Forgotten {
    pub seed: String,
    pub removed: bool,
}

/// The seeds, as this holder names them, of the wallets the manager still lists it holding and it
/// no longer has: each one to `forget_seed`. `has` says whether the holder has a seed of its own.
pub fn stale_seeds(listed: &[Wallet], has: impl Fn(&str) -> bool) -> Vec<String> {
    listed
        .iter()
        .filter_map(|w| w.holder_seed.as_deref().map(str::trim))
        .filter(|s| !s.is_empty() && !has(s))
        .map(String::from)
        .collect()
}

/// What a holder does about one of its seeds' names, from [`name_steps`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameStep {
    /// The person named it, here or in another app: keep this name. `seed` is the holder's own.
    Take { seed: String, name: String },
    /// No one has named it yet, and this holder has a name the person gave: send it once.
    Send { seed: String, name: String },
}

/// Each step that brings a holder's names and the manager's together. `own` gives the name the
/// person gave a seed in this holder, as the holder names the seed; none for a default.
pub fn name_steps(listed: &[Wallet], own: impl Fn(&str) -> Option<String>) -> Vec<NameStep> {
    listed
        .iter()
        .filter_map(|w| {
            let seed = w.holder_seed.as_deref()?.trim();
            let mine = own(seed).map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
            let theirs = w.name.trim();
            match mine {
                _ if w.named && !theirs.is_empty() => (mine.as_deref() != Some(theirs)).then(|| NameStep::Take {
                    seed: seed.into(),
                    name: theirs.into(),
                }),
                Some(m) if !w.named && m != theirs => Some(NameStep::Send {
                    seed: seed.into(),
                    name: m,
                }),
                _ => None,
            }
        })
        .collect()
}

pub fn read_data_key(reply: &str) -> Result<DataKey> {
    let v = parse_reply(reply)?;
    serde_json::from_value(v).map_err(|e| invalid(format!("data_key reply: {e}")))
}

pub fn read_account_key(reply: &str) -> Result<AccountKey> {
    let v = parse_reply(reply)?;
    serde_json::from_value(v).map_err(|e| invalid(format!("data_key reply: {e}")))
}

pub fn read_enrolled(reply: &str) -> Result<Enrolled> {
    let v = parse_reply(reply)?;
    serde_json::from_value(v).map_err(|e| invalid(format!("enroll_seed reply: {e}")))
}

pub fn read_named(reply: &str) -> Result<NameSeed> {
    let v = parse_reply(reply)?;
    serde_json::from_value(v).map_err(|e| invalid(format!("name_seed reply: {e}")))
}

pub fn read_forgotten(reply: &str) -> Result<Forgotten> {
    let v = parse_reply(reply)?;
    serde_json::from_value(v).map_err(|e| invalid(format!("forget_seed reply: {e}")))
}

pub fn read_wallets(reply: &str) -> Result<Vec<Wallet>> {
    let v = parse_reply(reply)?;
    serde_json::from_value(v.get("wallets").cloned().unwrap_or_default())
        .map_err(|e| invalid(format!("wallets reply: {e}")))
}

fn key_bytes(key: &DataKey) -> Result<Zeroizing<[u8; 32]>> {
    let raw = Zeroizing::new(hex::decode(key.key.expose().trim()).map_err(|_| invalid("data key: not hex"))?);
    let k: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| invalid("data key: not 32 bytes"))?;
    Ok(Zeroizing::new(k))
}

#[derive(Serialize, Deserialize)]
struct Boxed {
    v: u32,
    generation: u32,
    #[serde(rename = "box")]
    sealed: String,
}

/// `plain` under `key`, as `{ "v": 1, "generation": g, "box": hex(nonce ‖ ciphertext) }`. `aad`
/// names what it is, a file's name for instance, so one box can't stand in for another.
pub fn seal(key: &DataKey, plain: &[u8], aad: &str) -> Result<String> {
    let k = key_bytes(key)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = XChaCha20Poly1305::new(&(*k).into())
        .encrypt(
            &nonce,
            Payload {
                msg: plain,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| invalid("sealing failed"))?;
    let mut out = nonce.to_vec();
    out.extend(ct);
    serde_json::to_string(&Boxed {
        v: BOX_VERSION,
        generation: key.generation,
        sealed: hex::encode(out),
    })
    .map_err(|e| invalid(e.to_string()))
}

/// The generation a box was sealed at: the one to ask `data_key` for before opening it.
pub fn generation(sealed: &str) -> Result<u32> {
    let b: Boxed = serde_json::from_str(sealed).map_err(|e| invalid(format!("box: {e}")))?;
    if b.v != BOX_VERSION {
        return Err(invalid(format!("box version {}", b.v)));
    }
    Ok(b.generation)
}

/// What `seal` sealed, with the key of its generation. A box sealed under another key, or named
/// otherwise, doesn't open.
pub fn open(key: &DataKey, sealed: &str, aad: &str) -> Result<Zeroizing<Vec<u8>>> {
    let b: Boxed = serde_json::from_str(sealed).map_err(|e| invalid(format!("box: {e}")))?;
    if b.v != BOX_VERSION || b.generation != key.generation {
        return Err(invalid(format!(
            "box of generation {}, key of generation {}",
            b.generation, key.generation
        )));
    }
    let bytes = hex::decode(&b.sealed).map_err(|_| invalid("box: not hex"))?;
    if bytes.len() < 24 + 16 {
        return Err(invalid("box: too short"));
    }
    let (nonce, ct) = bytes.split_at(24);
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| invalid("box: nonce"))?;
    let k = key_bytes(key)?;
    XChaCha20Poly1305::new(&(*k).into())
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ct,
                aad: aad.as_bytes(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| SignerError::new(ErrorCode::WrongSecret, "this box doesn't open with that key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8, generation: u32) -> DataKey {
        DataKey {
            key: Secret::new(hex::encode([byte; 32])),
            generation,
        }
    }

    #[test]
    fn a_holder_takes_a_given_name_and_sends_its_own_only_while_none_is() {
        let reply = serde_json::json!({ "ok": true, "wallets": [
            { "seed": "s_1", "name": "White Card #1", "named": true, "locked": false, "holderSeed": "uid1" },
            { "seed": "s_2", "name": "Keycard 02246c2a", "locked": true, "holderSeed": "uid2" },
            { "seed": "s_3", "name": "Keycard 9f00aa11", "locked": true, "holderSeed": "uid3" },
            { "seed": "s_4", "name": "Same", "named": true, "locked": true, "holderSeed": "uid4" },
            { "seed": "s_5", "name": "Not mine", "named": true, "locked": true }
        ]});
        let listed = read_wallets(&reply.to_string()).unwrap();
        assert!(listed[0].named && !listed[1].named && listed[4].holder_seed.is_none());
        let own = |seed: &str| match seed {
            "uid1" => Some("Old name".to_string()),
            "uid2" => Some(" Savings ".to_string()),
            "uid4" => Some("Same".to_string()),
            _ => None,
        };
        assert_eq!(
            name_steps(&listed, own),
            vec![
                NameStep::Take {
                    seed: "uid1".into(),
                    name: "White Card #1".into()
                },
                NameStep::Send {
                    seed: "uid2".into(),
                    name: "Savings".into()
                },
            ],
            "uid3 has only the enrolled default, uid4 agrees already, s_5 is another holder's"
        );
        // An older manager lists no `named`: nothing is taken from it.
        let old =
            read_wallets(r#"{"ok":true,"wallets":[{"seed":"s","name":"n","locked":false,"holderSeed":"u"}]}"#).unwrap();
        assert_eq!(name_steps(&old, |_| None), vec![]);
        let named = read_named(r#"{"ok":true,"seed":"s_1","name":"White Card #1"}"#).unwrap();
        assert_eq!(
            named,
            NameSeed {
                seed: "s_1".into(),
                name: "White Card #1".into()
            }
        );
    }

    #[test]
    fn a_box_opens_with_its_key_and_name_only() {
        let sealed = seal(&key(1, 3), b"accounts", "accounts.json").unwrap();
        assert_eq!(generation(&sealed).unwrap(), 3);
        assert_eq!(
            open(&key(1, 3), &sealed, "accounts.json").unwrap().as_slice(),
            b"accounts"
        );
        assert!(open(&key(2, 3), &sealed, "accounts.json").is_err(), "another key");
        assert!(open(&key(1, 3), &sealed, "history.json").is_err(), "another name");
        assert!(
            open(&key(1, 2), &sealed, "accounts.json").is_err(),
            "another generation"
        );
        assert!(!sealed.contains(&hex::encode(b"accounts")));
    }

    #[test]
    fn replies_read_as_their_types() {
        let k = read_data_key(&format!(r#"{{"ok":true,"key":"{}","generation":1}}"#, "ab".repeat(32))).unwrap();
        assert_eq!(k.generation, 1);
        let a = read_account_key(&format!(
            r#"{{"ok":true,"key":"{}","generation":2,"seed":"s_1"}}"#,
            "ab".repeat(32)
        ))
        .unwrap();
        assert_eq!((a.seed.as_str(), a.key.generation), ("s_1", 2));
        assert_eq!(
            read_data_key(r#"{"ok":false,"code":"locked","error":"Card is locked"}"#)
                .unwrap_err()
                .code,
            ErrorCode::Locked
        );
        let e = read_enrolled(r#"{"ok":true,"seed":"s_1","new":true,"unlocked":true}"#).unwrap();
        assert_eq!(
            e,
            Enrolled {
                seed: "s_1".into(),
                new: true,
                unlocked: true
            }
        );
        let w =
            read_wallets(r#"{"ok":true,"wallets":[{"seed":"s_1","name":"Card","locked":true,"kinds":["keycard"]}]}"#)
                .unwrap();
        assert_eq!((w[0].name.as_str(), w[0].locked), ("Card", true));
        let f = read_forgotten(r#"{"ok":true,"seed":"s_1","removed":true}"#).unwrap();
        assert_eq!(
            f,
            Forgotten {
                seed: "s_1".into(),
                removed: true
            }
        );
    }

    #[test]
    fn a_holder_forgets_only_the_listed_seeds_of_its_own_it_no_longer_has() {
        let reply = serde_json::json!({ "ok": true, "wallets": [
            { "seed": "s_1", "name": "Kept", "locked": false, "holderSeed": "g_1" },
            { "seed": "s_2", "name": "Removed", "locked": true, "holderSeed": " g_2 " },
            { "seed": "s_3", "name": "Not mine", "locked": true },
            { "seed": "s_4", "name": "Blank", "locked": true, "holderSeed": " " }
        ]});
        let listed = read_wallets(&reply.to_string()).unwrap();
        assert_eq!(stale_seeds(&listed, |s| s == "g_1"), vec!["g_2".to_string()]);
        assert!(stale_seeds(&listed, |_| true).is_empty());
    }

    #[test]
    fn an_older_signers_origin_and_birthday_are_ignored() {
        let e: EnrollSeed = serde_json::from_str(
            r#"{"seed":"g_1","kind":"keystore","name":"Main","origin":"restored","birthday":"2021-11-14"}"#,
        )
        .unwrap();
        assert_eq!((e.seed.as_str(), e.name.as_str()), ("g_1", "Main"));
        let sent = serde_json::to_string(&e).unwrap();
        assert!(!sent.contains("origin") && !sent.contains("birthday"), "{sent}");
    }
}
