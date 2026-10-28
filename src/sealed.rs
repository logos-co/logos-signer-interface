//! A module's documents, one per seed, each sealed under its key from `data_key(seed, scope)`, in
//! one file: `{ "v": 1, "seeds": { "<seed>": <box> } }`, 0600. A seed's document opens when its key
//! arrives and is sealed again under the current generation; while it is locked, it is not read. A
//! document written before its seed's key is known waits in memory until it is.
//!
//! The key comes from the signer manager in the module's own time (`wallets_changed`), never from
//! inside a call the manager made to the module: see `docs/wallets.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::wallets::{self, DataKey};
use crate::wire::{ErrorCode, Result, SignerError};

const VERSION: u32 = 1;

fn io(e: impl std::fmt::Display) -> SignerError {
    SignerError::new(ErrorCode::Internal, e.to_string())
}

#[derive(Default, Serialize, Deserialize)]
struct File {
    v: u32,
    seeds: BTreeMap<String, String>,
}

pub struct SealedDocs {
    path: Option<PathBuf>,
    /// What the boxes are, in their associated data: the module's own name for the document.
    name: String,
    sealed: BTreeMap<String, String>,
    open: BTreeMap<String, (DataKey, Zeroizing<Vec<u8>>)>,
    pending: BTreeMap<String, Zeroizing<Vec<u8>>>,
}

/// Staged beside it at 0600 from creation, synced, renamed over it.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let staged = path.with_extension("json.staged");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&staged)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&staged, path)
}

impl SealedDocs {
    /// Nothing on disk, for tests.
    pub fn in_memory(name: impl Into<String>) -> Self {
        SealedDocs {
            path: None,
            name: name.into(),
            sealed: BTreeMap::new(),
            open: BTreeMap::new(),
            pending: BTreeMap::new(),
        }
    }

    /// The documents kept at `path`; none yet when it doesn't exist.
    pub fn load(path: impl Into<PathBuf>, name: impl Into<String>) -> Result<Self> {
        let path = path.into();
        let sealed = match std::fs::read(&path) {
            Ok(bytes) => {
                let f: File = serde_json::from_slice(&bytes).map_err(|e| io(format!("{}: {e}", path.display())))?;
                if f.v != VERSION {
                    return Err(io(format!("{}: version {}", path.display(), f.v)));
                }
                f.seeds
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(io(e)),
        };
        Ok(SealedDocs {
            path: Some(path),
            name: name.into(),
            sealed,
            open: BTreeMap::new(),
            pending: BTreeMap::new(),
        })
    }

    fn aad(&self, seed: &str) -> String {
        format!("{}\0{seed}", self.name)
    }

    fn save(&self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let body = serde_json::to_vec_pretty(&File {
            v: VERSION,
            seeds: self.sealed.clone(),
        })
        .map_err(io)?;
        write_private(path, &body).map_err(io)
    }

    /// Every seed it keeps a document for, locked or not.
    pub fn seeds(&self) -> Vec<String> {
        let mut out: Vec<String> = self.sealed.keys().chain(self.pending.keys()).cloned().collect();
        out.sort();
        out.dedup();
        out
    }

    /// The generation to ask `data_key` for to open the seed's document, or none when there is
    /// nothing sealed to open.
    pub fn wanted(&self, seed: &str) -> Option<u32> {
        if self.open.contains_key(seed) {
            return None;
        }
        self.sealed.get(seed).and_then(|b| wallets::generation(b).ok())
    }

    pub fn is_open(&self, seed: &str) -> bool {
        self.open.contains_key(seed)
    }

    /// Open the seed's document with the key of its box's generation, and seal it again, with
    /// whatever waited for it, under `current`.
    pub fn unlock(&mut self, seed: &str, box_key: &DataKey, current: &DataKey) -> Result<()> {
        let plain = match self.sealed.get(seed) {
            Some(b) => wallets::open(box_key, b, &self.aad(seed))?,
            None => Zeroizing::new(Vec::new()),
        };
        let plain = self.pending.remove(seed).unwrap_or(plain);
        let resealed = wallets::seal(current, &plain, &self.aad(seed))?;
        self.sealed.insert(seed.to_string(), resealed);
        self.open.insert(seed.to_string(), (current.clone(), plain));
        self.save()
    }

    /// The seed's document, while it is open or still waiting for its key.
    pub fn get(&self, seed: &str) -> Option<&[u8]> {
        self.open
            .get(seed)
            .map(|(_, p)| p.as_slice())
            .or_else(|| self.pending.get(seed).map(|p| p.as_slice()))
    }

    /// Every document that can be read now, by seed.
    pub fn readable(&self) -> Vec<(String, &[u8])> {
        let mut out: Vec<(String, &[u8])> = self.open.iter().map(|(s, (_, p))| (s.clone(), p.as_slice())).collect();
        out.extend(
            self.pending
                .iter()
                .filter(|(s, _)| !self.open.contains_key(*s))
                .map(|(s, p)| (s.clone(), p.as_slice())),
        );
        out
    }

    /// Write the seed's document: sealed under its key when it is open, else kept in memory until
    /// its key comes. A seed that is sealed and locked can't be written: its document would be lost.
    pub fn put(&mut self, seed: &str, plain: Vec<u8>) -> Result<()> {
        let plain = Zeroizing::new(plain);
        if let Some((key, _)) = self.open.get(seed) {
            let key = key.clone();
            let sealed = wallets::seal(&key, &plain, &self.aad(seed))?;
            self.sealed.insert(seed.to_string(), sealed);
            self.open.insert(seed.to_string(), (key, plain));
            return self.save();
        }
        if self.sealed.contains_key(seed) {
            return Err(SignerError::new(
                ErrorCode::Locked,
                "this wallet is locked: unlock it in the Signer app",
            ));
        }
        self.pending.insert(seed.to_string(), plain);
        Ok(())
    }

    /// Forget the seed's document, sealed or not.
    pub fn remove(&mut self, seed: &str) -> Result<()> {
        self.open.remove(seed);
        self.pending.remove(seed);
        if self.sealed.remove(seed).is_some() {
            self.save()?;
        }
        Ok(())
    }

    /// Forget every key and what it opened; documents still waiting for theirs stay.
    pub fn lock(&mut self) {
        self.open.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Secret;

    fn key(byte: u8, generation: u32) -> DataKey {
        DataKey {
            key: Secret::new(hex::encode([byte; 32])),
            generation,
        }
    }

    #[test]
    fn a_document_waits_for_its_key_then_opens_only_with_it_after_a_restart() {
        let dir = std::env::temp_dir().join(format!("sealed-docs-{}", std::process::id()));
        let path = dir.join("accounts.json");
        let _ = std::fs::remove_dir_all(&dir);
        let mut d = SealedDocs::load(&path, "accounts").unwrap();
        d.put("uid1", b"[\"0xabc\"]".to_vec()).unwrap();
        assert_eq!(d.get("uid1"), Some(&b"[\"0xabc\"]"[..]), "readable while waiting");
        assert!(!path.exists(), "nothing written before the key");
        d.unlock("uid1", &key(1, 0), &key(1, 0)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("uid1") && !text.contains("0xabc"), "{text}");

        let mut again = SealedDocs::load(&path, "accounts").unwrap();
        assert_eq!(again.seeds(), vec!["uid1".to_string()]);
        assert_eq!(again.get("uid1"), None, "locked after a restart");
        assert!(
            again.put("uid1", b"[]".to_vec()).is_err(),
            "a locked document isn't overwritten"
        );
        assert_eq!(again.wanted("uid1"), Some(0));
        assert!(again.unlock("uid1", &key(2, 0), &key(2, 0)).is_err(), "another key");
        again.unlock("uid1", &key(1, 0), &key(1, 1)).unwrap();
        assert_eq!(again.get("uid1"), Some(&b"[\"0xabc\"]"[..]));
        let mut third = SealedDocs::load(&path, "accounts").unwrap();
        assert_eq!(
            third.wanted("uid1"),
            Some(1),
            "sealed again under the current generation"
        );
        third.unlock("uid1", &key(1, 1), &key(1, 1)).unwrap();
        third.lock();
        assert_eq!(third.readable().len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn another_modules_document_doesnt_open_under_this_name() {
        let mut a = SealedDocs::in_memory("keycard accounts");
        a.unlock("uid", &key(1, 0), &key(1, 0)).unwrap();
        a.put("uid", b"x".to_vec()).unwrap();
        let sealed = a.sealed["uid"].clone();
        let mut b = SealedDocs::in_memory("shell accounts");
        b.sealed.insert("uid".into(), sealed);
        assert!(b.unlock("uid", &key(1, 0), &key(1, 0)).is_err());
    }
}
