//! The key that unlocks a seed's data: the public key at a reserved hardened path, the same from
//! every holder of the seed. The signer manager wraps the seed's own data key under it; nothing
//! signs at that path. Also what makes two signers' Bitcoin accounts one, and the path guards.

use std::str::FromStr;

use bip32::XPub;
use sha2::{Digest, Sha256};

use crate::verify::parse_path;
use crate::wire::{Chain, ErrorCode, Family, Result, SignerError};

/// "LOGO" in ASCII: a purpose no account uses.
pub const PURPOSE: u32 = 1_280_263_247;

fn invalid(msg: impl Into<String>) -> SignerError {
    SignerError::new(ErrorCode::Invalid, msg)
}

/// `m/1280263247'/n'`: a seed's unlock key at unlock index `n`. A seed moves to the next index when
/// its key may have leaked, such as a photographed QR answer.
pub fn unlock_key_path(index: u32) -> Result<String> {
    if index >= 0x8000_0000 {
        return Err(invalid(format!("unlock index {index}")));
    }
    Ok(format!("m/{PURPOSE}'/{index}'"))
}

/// A 33-byte compressed key, as a holder answers `unlock_key`.
pub fn check_unlock_key(hex_key: &str) -> Result<()> {
    let bytes = hex::decode(hex_key.trim()).map_err(|_| invalid("unlock key: not hex"))?;
    k256::PublicKey::from_sec1_bytes(&bytes)
        .ok()
        .filter(|_| bytes.len() == 33)
        .map(drop)
        .ok_or_else(|| invalid("unlock key: not a compressed public key"))
}

/// Under the reserved purpose, hardened or not: nothing may sign there.
pub fn is_reserved(path: &str) -> bool {
    parse_path(path)
        .ok()
        .and_then(|p| p.first().map(|c| c.index() == PURPOSE))
        .unwrap_or(false)
}

/// An EVM account's path sits under `m/44'/60'`.
pub fn evm_path_ok(path: &str) -> bool {
    parse_path(path).is_ok_and(|p| {
        p.len() >= 2 && p[0].is_hardened() && p[0].index() == 44 && p[1].is_hardened() && p[1].index() == 60
    })
}

/// What makes two signers' Bitcoin accounts one: `btc_` and 32 hex of a hash over the family, the
/// chain, the chain code and the key, whatever the xpub's metadata.
pub fn roster_key(family: Family, chain: Option<Chain>, xpub: &str) -> Result<String> {
    let x = XPub::from_str(xpub.trim()).map_err(|e| invalid(format!("xpub: {e}")))?;
    let json = |v: serde_json::Result<String>| v.map_err(|e| invalid(e.to_string()));
    let mut h = Sha256::new();
    h.update(json(serde_json::to_string(&family))?.as_bytes());
    h.update(json(serde_json::to_string(&chain))?.as_bytes());
    h.update(x.attrs().chain_code);
    h.update(x.public_key().to_encoded_point(true).as_bytes());
    Ok(format!("btc_{}", hex::encode(&h.finalize()[..16])))
}

/// The xpub is this account's: its roster key is `key`.
pub fn check_xpub(key: &str, family: Family, chain: Option<Chain>, xpub: &str) -> Result<()> {
    if roster_key(family, chain, xpub)? != key {
        return Err(invalid("the xpub is not this account's"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip32::{DerivationPath, Prefix, XPrv};

    fn tpub() -> String {
        let path = DerivationPath::from_str("m/84'/1'/0'").unwrap();
        XPrv::derive_from_path([7u8; 64], &path)
            .unwrap()
            .public_key()
            .to_string(Prefix::TPUB)
    }

    #[test]
    fn an_unlock_path_is_hardened_under_the_purpose() {
        assert_eq!(unlock_key_path(0).unwrap(), "m/1280263247'/0'");
        assert_eq!(unlock_key_path(1).unwrap(), "m/1280263247'/1'");
        assert!(unlock_key_path(0x8000_0000).is_err());
        assert!(is_reserved(&unlock_key_path(7).unwrap()));
        assert!(is_reserved("m/1280263247/0"));
        assert!(!is_reserved("m/84'/1'/0'/0/0"));
    }

    #[test]
    fn an_unlock_key_is_33_bytes_compressed() {
        let k = XPrv::derive_from_path([7u8; 64], &DerivationPath::from_str("m/1280263247'/0'").unwrap()).unwrap();
        let point = k.public_key().public_key().to_encoded_point(true);
        assert!(check_unlock_key(&hex::encode(point.as_bytes())).is_ok());
        assert!(check_unlock_key(&hex::encode(
            k.public_key().public_key().to_encoded_point(false).as_bytes()
        ))
        .is_err());
        assert!(check_unlock_key("02").is_err());
        assert!(check_unlock_key("zz").is_err());
    }

    #[test]
    fn evm_paths_sit_under_44_60() {
        assert!(evm_path_ok("m/44'/60'/0'/0/0"));
        assert!(!evm_path_ok("m/44'/0'/0'/0/0"));
        assert!(!evm_path_ok("m/1280263247'/0'"));
        assert!(!evm_path_ok("garbage"));
    }

    #[test]
    fn the_roster_key_ignores_xpub_metadata_and_checks() {
        let key = roster_key(Family::Bitcoin, Some(Chain::Test), &tpub()).unwrap();
        assert!(key.starts_with("btc_") && key.len() == 36);
        assert!(check_xpub(&key, Family::Bitcoin, Some(Chain::Test), &tpub()).is_ok());
        assert!(check_xpub(&key, Family::BitcoinTaproot, Some(Chain::Test), &tpub()).is_err());
    }
}
