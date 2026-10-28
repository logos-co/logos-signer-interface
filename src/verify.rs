//! Checking a signer's answer against public material only: the account's address or xpub.

use std::str::FromStr;

use bip32::{ChildNumber, XPub};
use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, VerifyingKey};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{schnorr, ProjectivePoint, PublicKey, Scalar};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

use crate::wire::{Account, ErrorCode, Family, HashItem, Result, Scheme, Signature, SignerError};

fn invalid(msg: impl Into<String>) -> SignerError {
    SignerError::new(ErrorCode::Invalid, msg)
}

pub fn hex32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.trim_start_matches("0x")).map_err(|e| invalid(format!("not hex: {e}")))?;
    b.try_into().map_err(|_| invalid("expected 32 bytes"))
}

fn hex64(s: &str) -> Result<[u8; 64]> {
    let b = hex::decode(s.trim_start_matches("0x")).map_err(|e| invalid(format!("not hex: {e}")))?;
    b.try_into().map_err(|_| invalid("expected 64 bytes"))
}

/// `m/84'/1'/0'/0/5` → child numbers. `'` and `h` both mark hardened.
pub fn parse_path(path: &str) -> Result<Vec<ChildNumber>> {
    let rest = path
        .strip_prefix("m")
        .ok_or_else(|| invalid(format!("path {path:?} must start with m")))?;
    let mut out = Vec::new();
    for part in rest.split('/').skip(1) {
        let (num, hardened) = match part.strip_suffix('\'').or_else(|| part.strip_suffix('h')) {
            Some(n) => (n, true),
            None => (part, false),
        };
        let index: u32 = num
            .parse()
            .map_err(|_| invalid(format!("bad path component {part:?}")))?;
        out.push(ChildNumber::new(index, hardened).map_err(|_| invalid(format!("index too large: {part:?}")))?);
    }
    Ok(out)
}

/// The levels `path` adds below `account_path`, all unhardened, or an error.
pub fn relative(account_path: &str, path: &str) -> Result<Vec<ChildNumber>> {
    let base = parse_path(account_path)?;
    let full = parse_path(path)?;
    if full.len() <= base.len() || full[..base.len()] != base[..] {
        return Err(invalid(format!("{path} is not below the account's {account_path}")));
    }
    let rest = full[base.len()..].to_vec();
    if rest.iter().any(|c| c.is_hardened()) {
        return Err(invalid(format!(
            "{path}: an account signs only unhardened paths below it"
        )));
    }
    Ok(rest)
}

/// The public key at `path`, derived from the account's xpub.
pub fn derive(xpub: &str, account_path: &str, path: &str) -> Result<PublicKey> {
    let mut key = XPub::from_str(xpub).map_err(|e| invalid(format!("xpub: {e}")))?;
    for child in relative(account_path, path)? {
        key = key.derive_child(child).map_err(|e| invalid(format!("derive: {e}")))?;
    }
    Ok(PublicKey::from(key.public_key()))
}

pub fn evm_address(key: &PublicKey) -> String {
    let point = key.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let t = Sha256::digest(tag.as_bytes());
    Sha256::new()
        .chain_update(t)
        .chain_update(t)
        .chain_update(data)
        .finalize()
        .into()
}

/// BIP86: the internal key's x-only form tweaked by its own hash, with no script tree.
pub fn bip86_tweak(internal: &PublicKey) -> Result<(Scalar, schnorr::VerifyingKey)> {
    let x = internal.as_affine().x();
    let even = schnorr::VerifyingKey::from_bytes(&x).map_err(|_| invalid("internal key"))?;
    let t = Option::<Scalar>::from(Scalar::from_repr(tagged_hash("TapTweak", &x).into()))
        .ok_or_else(|| invalid("tweak out of range"))?;
    let q = ProjectivePoint::from(*even.as_affine()) + ProjectivePoint::GENERATOR * t;
    let out = schnorr::VerifyingKey::from_bytes(&q.to_affine().x()).map_err(|_| invalid("output key"))?;
    Ok((t, out))
}

/// The key an ECDSA signature over `digest` recovers to, low or high S.
pub fn recover_key(digest: &[u8; 32], sig: &[u8; 64], recovery_id: u8) -> Result<PublicKey> {
    let sig = EcdsaSignature::from_slice(sig).map_err(|_| invalid("signature"))?;
    let mut id = RecoveryId::from_byte(recovery_id).ok_or_else(|| invalid("recovery id"))?;
    let sig = match sig.normalize_s() {
        Some(low) => {
            id = RecoveryId::new(!id.is_y_odd(), id.is_x_reduced());
            low
        }
        None => sig,
    };
    let key = VerifyingKey::recover_from_prehash(digest, &sig, id).map_err(|_| invalid("no key recovers"))?;
    Ok(PublicKey::from(&key))
}

/// The address an EVM signature recovers to.
pub fn recover_evm(digest: &[u8; 32], sig: &[u8; 64], recovery_id: u8) -> Result<String> {
    let sig = EcdsaSignature::from_slice(sig).map_err(|_| invalid("signature"))?;
    if sig.normalize_s().is_some() {
        return Err(invalid("high-S signature"));
    }
    let id = RecoveryId::from_byte(recovery_id).ok_or_else(|| invalid("recovery id"))?;
    let key = VerifyingKey::recover_from_prehash(digest, &sig, id).map_err(|_| invalid("no key recovers"))?;
    Ok(evm_address(&PublicKey::from(&key)))
}

pub fn verify_ecdsa(digest: &[u8; 32], sig: &[u8; 64], key: &PublicKey) -> Result<()> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let sig = EcdsaSignature::from_slice(sig).map_err(|_| invalid("signature"))?;
    if sig.normalize_s().is_some() {
        return Err(invalid("high-S signature"));
    }
    VerifyingKey::from(key)
        .verify_prehash(digest, &sig)
        .map_err(|_| invalid("ECDSA signature does not verify"))
}

pub fn verify_bip340(digest: &[u8; 32], sig: &[u8; 64], key: &schnorr::VerifyingKey) -> Result<()> {
    let sig = schnorr::Signature::try_from(&sig[..]).map_err(|_| invalid("signature"))?;
    key.verify_raw(digest, &sig)
        .map_err(|_| invalid("BIP340 signature does not verify"))
}

/// Does `sig` sign `item` for `account`, with the key the account's public material says it must?
pub fn check(account: &Account, item: &HashItem, sig: &Signature) -> Result<()> {
    let digest = hex32(&item.digest)?;
    let bytes = hex64(&sig.signature)?;
    match (account.family, item.scheme) {
        (Family::Evm, Scheme::Evm) => {
            let want = account
                .address
                .as_deref()
                .ok_or_else(|| invalid("EVM account without an address"))?;
            let id = sig
                .recovery_id
                .ok_or_else(|| invalid("EVM signature without a recovery id"))?;
            let got = recover_evm(&digest, &bytes, id)?;
            if !got.eq_ignore_ascii_case(want) {
                return Err(invalid(format!("signature recovers to {got}, not {want}")));
            }
            Ok(())
        }
        (Family::Bitcoin, Scheme::Ecdsa) | (Family::BitcoinTaproot, Scheme::Bip86) => {
            let (xpub, base) = match (&account.xpub, &account.path) {
                (Some(x), Some(p)) => (x, p),
                _ => return Err(invalid("Bitcoin account without an xpub and a path")),
            };
            let path = item
                .path
                .as_deref()
                .ok_or_else(|| invalid("Bitcoin item without a path"))?;
            let key = derive(xpub, base, path)?;
            if item.scheme == Scheme::Ecdsa {
                if sig.pubkey != hex::encode(key.to_encoded_point(true).as_bytes()) {
                    return Err(invalid("answer names another key"));
                }
                return verify_ecdsa(&digest, &bytes, &key);
            }
            let (_, output) = bip86_tweak(&key)?;
            if sig.pubkey != hex::encode(output.to_bytes()) {
                return Err(invalid("answer names another key"));
            }
            verify_bip340(&digest, &bytes, &output)
        }
        (family, scheme) => Err(SignerError::new(
            ErrorCode::Unsupported,
            format!("{scheme:?} does not sign for a {family:?} account"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // From bitcoin/bips at 927b6de9915c (2026-10-02), BIP84's and BIP86's test vectors.
    const BIP84_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    const BIP86_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";
    const BIP86_INTERNAL: &str = "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115";
    const BIP86_OUTPUT: &str = "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c";

    #[test]
    fn bip84_vector_gives_the_published_keys() {
        for (path, want) in [
            (
                "m/84'/0'/0'/0/0",
                "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
            ),
            (
                "m/84'/0'/0'/1/0",
                "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6",
            ),
        ] {
            let key = derive(BIP84_ZPUB, "m/84'/0'/0'", path).unwrap();
            assert_eq!(hex::encode(key.to_encoded_point(true).as_bytes()), want, "{path}");
        }
    }

    #[test]
    fn bip86_vector_gives_the_published_internal_and_output_keys() {
        let key = derive(BIP86_XPUB, "m/86'/0'/0'", "m/86'/0'/0'/0/0").unwrap();
        assert_eq!(hex::encode(key.as_affine().x()), BIP86_INTERNAL);
        let (_, out) = bip86_tweak(&key).unwrap();
        assert_eq!(hex::encode(out.to_bytes()), BIP86_OUTPUT);
    }

    #[test]
    fn paths_outside_or_hardened_below_the_account_are_refused() {
        assert!(relative("m/84'/1'/0'", "m/84'/1'/1'/0/0").is_err());
        assert!(relative("m/84'/1'/0'", "m/84'/1'/0'/0'/0").is_err());
        assert!(relative("m/84'/1'/0'", "m/84'/1'/0'").is_err());
        assert_eq!(relative("m/84'/1'/0'", "m/84h/1h/0h/1/7").unwrap().len(), 2);
    }
}
